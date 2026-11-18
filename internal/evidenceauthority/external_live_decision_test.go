package evidenceauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	certpem "encoding/pem"
	"path/filepath"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-decision/internal/api"
	"github.com/avaargsh/agent-decision/internal/decision"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This test requires the real ACP publication process and the real Runtime
// authority process observing the SAME recovered Temporal business Turn.
// It owns only isolated test service observations, source registry and
// Decision database. It never seeds ACP or Runtime rows.
func TestExternalLiveDecisionCore(t *testing.T) {
	if os.Getenv("DECISION_EXTERNAL_LIVE_CORE") != "1" {
		t.Skip("only the cross-repository actual business Run gate")
	}
	required := func(name string) string {
		t.Helper()
		s := os.Getenv(name)
		if s == "" { t.Fatalf("missing %s", name) }
		return s
	}
	read := func(name string) []byte {
		t.Helper()
		b,err:=os.ReadFile(required(name)); if err!=nil{t.Fatal(err)}; return b
	}
	ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
	defer cancel()
	tenant,runID,invocation:=required("DECISION_LIVE_TENANT"),required("DECISION_LIVE_RUN"),required("DECISION_LIVE_INVOCATION")
	agent:=required("DECISION_LIVE_AGENT")
	pem:=read("DECISION_LIVE_ROOTS")
	roots:=x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem){t.Fatal("missing trusted server roots")}
	clientRoots:=x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(read("DECISION_LIVE_CLIENT_CA")){t.Fatal("missing Decision client CA")}
	clientCert,err:=tls.LoadX509KeyPair(required("DECISION_LIVE_CLIENT_CERT"),required("DECISION_LIVE_CLIENT_KEY"))
	if err!=nil{t.Fatal(err)}
	acpKey:=ed25519.PublicKey(read("DECISION_LIVE_ACP_PUBLIC_KEY"))
	// A separate isolated CA issues the independent source server and
	// Runtime-to-Decision test client certificates; it is not an ACP signer.
	caPub,caKey,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil{t.Fatal(err)}
	now:=time.Now().UTC()
	template:=&x509.Certificate{SerialNumber:big.NewInt(1),NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
		IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,caPub,caKey)
	if err!=nil{t.Fatal(err)}
	ca,err:=x509.ParseCertificate(der)
	if err!=nil{t.Fatal(err)}
	roots.AddCert(ca)
	inboundRoots:=x509.NewCertPool()
	inboundRoots.AddCert(ca)
	serial:=int64(2)
	issue:=func(id string,server bool)tls.Certificate{
		t.Helper()
		pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
		uri,err:=url.Parse(id);if err!=nil{t.Fatal(err)}
		leaf:=&x509.Certificate{SerialNumber:big.NewInt(serial),NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
			KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},URIs:[]*url.URL{uri}}
		serial++
		if server{leaf.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth};leaf.IPAddresses=[]net.IP{net.ParseIP("127.0.0.1")}}
		b,err:=x509.CreateCertificate(rand.Reader,leaf,ca,pub,caKey);if err!=nil{t.Fatal(err)}
		return tls.Certificate{Certificate:[][]byte{b,der},PrivateKey:key}
	}
	listen:=func(h http.Handler,id string,clients *x509.CertPool)*httptest.Server{
		t.Helper()
		s:=httptest.NewUnstartedServer(h)
		s.TLS=&tls.Config{MinVersion:tls.VersionTLS13,ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:clients,Certificates:[]tls.Certificate{issue(id,true)}}
		s.StartTLS();t.Cleanup(s.Close);return s
	}
	dsn:=required("DECISION_LIVE_DATABASE_URL")
	admin,err:=sql.Open("pgx",dsn);if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = admin.Close()})
	sqlRun:=func(q string){
		t.Helper()
		if _,err:=admin.ExecContext(ctx,q);err!=nil{t.Fatalf("isolated database provisioning: %v",err)}
	}
	base,err:=pgx.ParseConfig(dsn);if err!=nil{t.Fatal(err)}
	seed:=fmt.Sprintf("%d",time.Now().UnixNano())
	newSchema:=func(prefix string)string{
		schema:=prefix+"_"+seed;sqlRun("CREATE SCHEMA "+schema)
		t.Cleanup(func(){if _,err:=admin.Exec("DROP SCHEMA "+schema+" CASCADE");err!=nil{t.Error("schema cleanup failed")}})
		return schema
	}
	login:=func(schema,kind string,grants []string)*sql.DB{
		t.Helper()
		var random [16]byte
		if _,err:=rand.Read(random[:]);err!=nil{t.Fatal(err)}
		password:=hex.EncodeToString(random[:]);name:="live_"+kind+"_"+password[:16]
		sqlRun("CREATE ROLE "+name+" LOGIN PASSWORD '"+password+"'")
		t.Cleanup(func(){
			if _,err:=admin.Exec("DROP OWNED BY "+name);err!=nil{t.Error("role grant cleanup failed")}
			if _,err:=admin.Exec("DROP ROLE "+name);err!=nil{t.Error("role cleanup failed")}
		})
		sqlRun("GRANT USAGE ON SCHEMA "+schema+" TO "+name)
		for _,g:=range grants{sqlRun("GRANT "+g+" TO "+name)}
		cfg:=base.Copy();cfg.User=name;cfg.Password=password;cfg.RuntimeParams["search_path"]=schema+", pg_catalog, pg_temp"
		db:=stdlib.OpenDB(*cfg);t.Cleanup(func(){_ = db.Close()})
		if err:=db.PingContext(ctx);err!=nil{t.Fatal("independent database LOGIN unavailable")}
		return db
	}
	// Real HTTP faults plus an actual configuration change. The observed
	// counter/log/config bytes come from network reads of this service.
	var mu sync.Mutex
	failures,version:=0,1
	var log bytes.Buffer
	changed:=[]byte{}
	mux:=http.NewServeMux()
	mux.HandleFunc("/checkout",func(w http.ResponseWriter,_ *http.Request){
		mu.Lock();failures++;fmt.Fprintf(&log,"checkout status=500 version=%d\n",version);mu.Unlock()
		http.Error(w,"isolated failure",500)
	})
	mux.HandleFunc("/change",func(w http.ResponseWriter,r *http.Request){
		mu.Lock();defer mu.Unlock()
		if r.Method==http.MethodPost{before:=version;version++;changed=[]byte(fmt.Sprintf("version %d -> %d\n",before,version))}
		_,_=w.Write(changed)
	})
	mux.HandleFunc("/logs",func(w http.ResponseWriter,_ *http.Request){mu.Lock();defer mu.Unlock();_,_=w.Write(log.Bytes())})
	mux.HandleFunc("/metrics",func(w http.ResponseWriter,_ *http.Request){mu.Lock();defer mu.Unlock();fmt.Fprintf(w,"http_requests_failed_total %d\n",failures)})
	service:=httptest.NewServer(mux);defer service.Close()
	started:=time.Now().UTC()
	pulse:=func(method,path string,want int)[]byte{
		t.Helper()
		req,err:=http.NewRequestWithContext(ctx,method,service.URL+path,nil);if err!=nil{t.Fatal(err)}
		res,err:=service.Client().Do(req);if err!=nil{t.Fatal(err)}
		defer res.Body.Close()
		b,err:=io.ReadAll(res.Body);if err!=nil||res.StatusCode!=want{t.Fatalf("source observation failed %v",err)}
		return b
	}
	pulse("POST","/change",200)
	for i:=0;i<3;i++{pulse("GET","/checkout",500)}
	content:=map[string][]byte{"metrics":pulse("GET","/metrics",200),"logs":pulse("GET","/logs",200),"change":pulse("GET","/change",200)}
	if string(content["metrics"])!="http_requests_failed_total 3\n" ||
		strings.Count(string(content["logs"]),"checkout status=500 version=2")!=3 || string(content["change"])!="version 1 -> 2\n"{
		t.Fatal("actual source controls did not observe the requested service behavior")
	}
	cfg:=decision.LiveAuthorityConfig{
		TenantID:tenant,Runtime:decision.AuthorityEndpoint{Origin:required("DECISION_LIVE_RUNTIME_ORIGIN"),SPIFFEID:"spiffe://example.org/runtime-decision"},
		ACP:decision.AuthorityEndpoint{Origin:required("DECISION_LIVE_ACP_ORIGIN"),SPIFFEID:"spiffe://example.org/acp"},
		ACPKey:acpKey,TLS:decision.AuthorityTLS{Roots:roots,Certificate:clientCert},
	}
	var refs []decision.EvidenceRef
	var revoke func()
	for _,kind:=range []string{"metrics","logs","change"}{
		schema:=newSchema("source_"+kind)
		if err:=Install(ctx,admin,schema);err!=nil{t.Fatal(err)}
		readGrants:=[]string{"SELECT ON "+schema+".evidence_publications,"+schema+".evidence_revocations"}
		readerDB:=login(schema,"source_reader",readGrants)
		pubDB:=login(schema,"source_pub",append(append([]string{},readGrants...),"INSERT ON "+schema+".evidence_publications"))
		revDB:=login(schema,"source_revoke",append(append([]string{},readGrants...),"INSERT ON "+schema+".evidence_revocations"))
		pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
		scope:=decision.EvidenceSourceScope{TenantID:tenant,AgentID:agent,RunID:runID,Service:"payments",ResourceRef:"service:payments",
			SourceID:"live-"+kind,Source:"isolated-"+kind,SourceVersion:"1.0.0",EvidenceType:kind,SchemaVersion:"1.0.0",MaxAge:time.Hour,MaxLifetime:time.Hour}
		collected:=time.Now().UTC()
		ref,proof,err:=decision.PublishEvidence(scope,decision.EvidenceObservation{Ref:"actual-"+kind,ObservedFrom:started,ObservedTo:collected,
			ObservedAt:collected,CollectedAt:collected,ExpiresAt:collected.Add(10*time.Minute)},content[kind],key,collected)
		if err!=nil{t.Fatal(err)}
		publisher,err:=New(pubDB,schema,scope,pub);if err!=nil{t.Fatal(err)}
		if err:=publisher.Publish(ctx,ref,proof,collected);err!=nil{t.Fatal(err)}
		reader,err:=New(readerDB,schema,scope,pub);if err!=nil{t.Fatal(err)}
		h,err:=NewReadHandler(reader,"spiffe://example.org/decision");if err!=nil{t.Fatal(err)}
		id:="spiffe://evidence.example/"+kind
		source:=listen(h,id,clientRoots)
		cfg.Evidence=append(cfg.Evidence,decision.EvidenceAuthorityPin{Endpoint:decision.AuthorityEndpoint{Origin:source.URL,SPIFFEID:id},Scope:scope,PublicKey:pub})
		refs=append(refs,ref)
		if kind=="metrics"{
			revoker,err:=New(revDB,schema,scope,pub);if err!=nil{t.Fatal(err)}
			revoke=func(){if err:=revoker.Revoke(ctx,ref,"SOURCE_REVOKED");err!=nil{t.Fatal(err)}}
		}
	}
	schema:=newSchema("live_decision")
	if err:=decision.MigrateInSchema(ctx,admin,schema);err!=nil{t.Fatal(err)}
	app:=login(schema,"decision_app",[]string{"SELECT, INSERT ON "+schema+".decision_records","INSERT ON "+schema+".outbox_events"})
	att:=login(schema,"decision_attest",[]string{"SELECT ON "+schema+".schema_migrations"})
	if err:=decision.VerifyRuntimeDatabaseRole(ctx,app,schema,decision.RuntimeRoleApplication);err!=nil{t.Fatal(err)}
	authority,err:=decision.NewLiveAuthority(cfg);if err!=nil{t.Fatal(err)}
	store:=decision.NewPostgresStore(app)
	const runtimeCaller="spiffe://example.org/runtime-worker"
	handler,err:=api.NewTrustedTurnHandler(store,authority,runtimeCaller,func(ctx context.Context)error{
		return decision.VerifyInstalledCatalogInSchema(ctx,att,schema)
	})
	if err!=nil{t.Fatal(err)}
	server:=listen(handler,"spiffe://example.org/decision-api",inboundRoots)
    continuationDir := os.Getenv("DECISION_LIVE_RUNTIME_CONTINUATION_DIR")
    if continuationDir != "" {
        // The Runtime owns the key and creates this CSR before invoking Decision.
        // Only public certificate material crosses this isolated process boundary.
        csrDER, err := os.ReadFile(filepath.Join(continuationDir, "worker.csr"))
        if err != nil { t.Fatal(err) }
        workerCert, err := issueRuntimeWorkerCertificate(csrDER, ca, caKey, time.Now().UTC())
        if err != nil { t.Fatalf("untrusted Runtime CSR: %v", err) }
        write := func(name string, content []byte) {
            t.Helper()
            if err := os.WriteFile(filepath.Join(continuationDir, name), content, 0600); err != nil { t.Fatal(err) }
        }
        write("worker-cert.pem",workerCert)
        write("decision-ca.pem",certpem.EncodeToMemory(&certpem.Block{Type:"CERTIFICATE",Bytes:der}))
        // Publish origin last: Runtime may connect only after cert and CA exist.
        write("origin",[]byte(server.URL))
    }
	makeClient:=func(id string)*http.Client{
		h:=&http.Client{Timeout:40*time.Second,Transport:&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS13,RootCAs:inboundRoots,
			Certificates:[]tls.Certificate{issue(id,false)}}}}
		t.Cleanup(h.CloseIdleConnections);return h
	}
	runtime:=makeClient(runtimeCaller)
	request:=api.TurnRequest{RunID:runID,InvocationID:invocation,Evidence:refs}
	call:=func(client *http.Client,method,path string,value any,want int)[]byte{
		t.Helper()
		var b []byte;var err error
		if value!=nil{b,err=json.Marshal(value);if err!=nil{t.Fatal(err)}}
		req,err:=http.NewRequestWithContext(ctx,method,server.URL+path,bytes.NewReader(b));if err!=nil{t.Fatal(err)}
		req.Header.Set("Content-Type","application/json")
		req.Header.Set("X-Forwarded-Client-Cert",runtimeCaller)
		res,err:=client.Do(req);if err!=nil{t.Fatal(err)}
		defer res.Body.Close()
		raw,err:=io.ReadAll(res.Body);if err!=nil||res.StatusCode!=want{t.Fatalf("actual Decision endpoint %d want %d: %s %v",res.StatusCode,want,raw,err)}
		return raw
	}
	inspectPath:=api.InspectTurnPrefix+runID+"/"+invocation
	var inspection api.TurnInspection
	if err:=json.Unmarshal(call(runtime,"GET",inspectPath,nil,200),&inspection);err!=nil||inspection.Status!="ABSENT_UNCERTAIN"||inspection.Record!=nil{t.Fatal("absence was overstated")}
	// Revalidation is read-only and must never create a DecisionRecord.
	verifyPath := inspectPath + "/verify"
	call(runtime, "GET", verifyPath, nil, 404)
	call(makeClient("spiffe://example.org/agent"), "GET", verifyPath, nil, 401)
	call(makeClient("spiffe://example.org/agent"),"POST",api.PlanTurnPath,request,401)
	bad:=request;bad.Evidence=append([]decision.EvidenceRef{},refs...);bad.Evidence[0].SHA256=strings.Repeat("a",64)
	call(runtime,"POST",api.PlanTurnPath,bad,403)
	bad=request;bad.InvocationID="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	call(runtime,"POST",api.PlanTurnPath,bad,403)
	// The real network transport receives the committed 201 and drops
	// it before the Runtime caller can observe any response. The next
	// operation is authenticated Inspect, not another Plan submission.
	lost := &lostDecisionResponse{upstream: runtime.Transport}
	lostClient := &http.Client{Transport: lost, Timeout: 40 * time.Second}
	rawRequest, err := json.Marshal(request)
	if err != nil { t.Fatal(err) }
	plan, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+api.PlanTurnPath, bytes.NewReader(rawRequest))
	if err != nil { t.Fatal(err) }
	plan.Header.Set("Content-Type", "application/json")
	plan.GetBody = nil
	if res, err := lostClient.Do(plan); err == nil || res != nil || !lost.dropped || lost.calls != 1 {
		t.Fatalf("real committed response loss was not observed: %v calls=%d", err, lost.calls)
	}
	if err:=json.Unmarshal(call(runtime,"GET",inspectPath,nil,200),&inspection);err!=nil||inspection.Status!="FOUND"||inspection.Record==nil{
		t.Fatal("committed DecisionRecord not independently recoverable")
	}
	record:=inspection.Record
	if record.RunID!=runID||record.InvocationID!=invocation||record.Status!=decision.StatusProposed||
		len(record.Plan.Steps)!=3||len(record.Evidence)!=3||record.Plan.PlanHash==""{
		t.Fatalf("real Decision Core did not create same-Run read-only proposal: %+v",record)
	}
	for _,step:=range record.Plan.Steps{if !step.ReadOnly||len(step.EvidenceRefs)==0{t.Fatal("unsafe plan")}}
	var rows,events int
	if err:=admin.QueryRowContext(ctx,"SELECT (SELECT count(*) FROM "+schema+".decision_records),(SELECT count(*) FROM "+schema+".outbox_events)").Scan(&rows,&events);err!=nil||rows!=1||events!=1{
		t.Fatalf("DecisionRecord/outbox atomic count %d/%d %v",rows,events,err)
	}
	// A fresh continuation receipt is not historical inspection or a Permit.
	type continuationReceipt struct {
		SchemaVersion string `json:"schema_version"`
		Authority decision.RuntimeDecisionAuthority `json:"authority"`
		DecisionID string `json:"decision_id"`
		RecordSHA256 string `json:"record_sha256"`
		PlanHash string `json:"plan_hash"`
	}
	var verified continuationReceipt
	if err := json.Unmarshal(call(runtime, "GET", verifyPath, nil, 200), &verified); err != nil ||
		verified.SchemaVersion != "decision.continuation.v1" || verified.Authority.RunID != runID ||
		verified.Authority.InvocationID != invocation || verified.Authority.AttemptID == "" ||
		verified.Authority.BreakerEpoch < 1 || verified.Authority.BreakerVersion < 1 ||
		verified.DecisionID != record.DecisionID || verified.PlanHash != record.Plan.PlanHash ||
		len(verified.RecordSHA256) != 64 {
		t.Fatalf("invalid fresh continuation receipt: %+v %v", verified, err)
	}
	var again continuationReceipt
	if err := json.Unmarshal(call(runtime, "GET", verifyPath, nil, 200), &again); err != nil || again != verified {
		t.Fatal("unchanged committed decision did not revalidate identically")
	}
	if err := admin.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM "+schema+".decision_records),(SELECT count(*) FROM "+schema+".outbox_events)").Scan(&rows, &events); err != nil || rows != 1 || events != 1 {
		t.Fatal("verification created mutable decision or outbox state")
	}
	if continuationDir != "" {
        if err := fixtureMarker(ctx, filepath.Join(continuationDir, "runtime-accepted")); err != nil {
            t.Fatalf("Runtime did not commit authentic Decision receipt before revocation: %v", err)
        }
    }
	// Current source revocation blocks plan replay through this trusted API.
	// Historical read remains an observation and must never authorize effect.
	revoke()
    if continuationDir != "" {
        if err := os.WriteFile(filepath.Join(continuationDir, "source-revoked"), []byte("revoked"), 0600); err != nil { t.Fatal(err) }
    }
	call(runtime, "GET", verifyPath, nil, 403)
	call(runtime,"POST",api.PlanTurnPath,request,403)
	if err:=json.Unmarshal(call(runtime,"GET",inspectPath,nil,200),&inspection);err!=nil||inspection.Record==nil||inspection.Record.DecisionID!=record.DecisionID{t.Fatal("historical record lost")}
    if continuationDir != "" {
        if err := fixtureMarker(ctx, filepath.Join(continuationDir, "runtime-denied")); err != nil {
            t.Fatalf("Runtime did not independently reject revoked source: %v", err)
        }
    }
	t.Logf("actual same-Run DecisionRecord %s invocation %s PROPOSED with three real observations, one outbox and inspect recovery",record.DecisionID,invocation)
}

type lostDecisionResponse struct {
	upstream http.RoundTripper
	calls int
	dropped bool
}

func (l *lostDecisionResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	l.calls++
	res, err := l.upstream.RoundTrip(r)
	if err != nil { return nil, err }
	if res.StatusCode != http.StatusCreated {
		return res, nil
	}
	_, err = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if err != nil { return nil, err }
	l.dropped = true
	return nil, io.ErrUnexpectedEOF
}
