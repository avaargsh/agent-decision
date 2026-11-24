package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// AuthorityEndpoint is a deployment-controlled origin and distinct peer
// pin. A caller cannot supply URLs, keys, transport or proxy configuration.
type AuthorityEndpoint struct {
	Origin, SPIFFEID string
}

type AuthorityTLS struct {
	Roots *x509.CertPool
	Certificate tls.Certificate
}

type EvidenceAuthorityPin struct {
	Endpoint AuthorityEndpoint
	Scope EvidenceSourceScope
	PublicKey ed25519.PublicKey
}

type LiveAuthorityConfig struct {
	TenantID string
	Runtime, ACP AuthorityEndpoint
	ACPKey ed25519.PublicKey
	TLS AuthorityTLS
	Evidence []EvidenceAuthorityPin
}

type RuntimeDecisionAuthority struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id"`
	RunID          string `json:"run_id"`
	RunIntentID    string `json:"run_intent_id"`
	RequestDigest  string `json:"request_digest"`
	WorkflowID     string `json:"workflow_id"`
	ExecutionID    string `json:"execution_id"`
	AttemptID      string `json:"attempt_id"`
	TurnID         string `json:"turn_id"`
	InvocationID   string `json:"invocation_id"`
	AgentID        string `json:"agent_id"`
	AgentReleaseID string `json:"agent_release_id"`
	SessionID      string `json:"session_id"`
	ProjectID      string `json:"project_id"`
	SubjectID      string `json:"subject_id"`
	ActorID        string `json:"actor_id"`
	PolicyRevision string `json:"policy_revision"`
	ConfigDigest   string `json:"config_digest"`
	InputDigest    string `json:"input_digest"`
	Phase          string `json:"phase"`
	Status         string `json:"status"`
	BreakerState   string `json:"breaker_state"`
	BreakerEpoch   int64  `json:"breaker_epoch"`
	BreakerVersion int64  `json:"breaker_version"`
}

func (r RuntimeDecisionAuthority) acpBinding() ACPRunBinding {
	return ACPRunBinding{TenantID:r.TenantID, RunIntentID:r.RunIntentID, RunID:r.RunID,
		RequestDigest:r.RequestDigest, ProjectID:r.ProjectID, AgentID:r.AgentID, AgentReleaseID:r.AgentReleaseID,
		SessionID:r.SessionID, SubjectID:r.SubjectID, ActorID:r.ActorID,
		PolicyRevision:r.PolicyRevision, ConfigDigest:r.ConfigDigest}
}

func (r RuntimeDecisionAuthority) valid(tenant, runID, invocation string) bool {
	if r.SchemaVersion != "runtime.decision-authority.v1" || r.TenantID != tenant ||
		r.RunID != runID || r.InvocationID != invocation || r.TurnID != invocation ||
		r.WorkflowID != "agent-run/v1/"+runID || r.Status != "RUNNING" ||
		r.BreakerState != "CLOSED" || r.BreakerEpoch < 1 || r.BreakerVersion < 1 ||
		r.Phase != "WAITING_AUTHORITY" || !acpDigest(r.RequestDigest) || !acpDigest(r.ConfigDigest) ||
		!acpDigest(r.InputDigest) || r.SubjectID != r.ActorID {
		return false
	}
	for _, id := range []string{r.RunID,r.RunIntentID,r.ExecutionID,r.AttemptID,r.TurnID,r.InvocationID} {
		if !acpUUID.MatchString(id) { return false }
	}
	for _, id := range []string{r.TenantID,r.ProjectID,r.AgentID,r.AgentReleaseID,r.SessionID,r.SubjectID,r.ActorID,r.PolicyRevision} {
		if !nameRe.MatchString(id) { return false }
	}
	return true
}

type authorityClient struct {
	origin string
	client *http.Client
}

func validSPIFFE(id string) bool {
	u, err := url.Parse(id)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Port() == "" &&
		u.Path != "" && u.Path != "/" && u.User == nil && u.Opaque == "" && u.RawPath == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.String() == id
}

func newAuthorityClient(e AuthorityEndpoint, c AuthorityTLS) (*authorityClient,error) {
	u, err := url.Parse(e.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.String() != e.Origin || !validSPIFFE(e.SPIFFEID) || c.Roots == nil ||
		len(c.Certificate.Certificate) == 0 || c.Certificate.PrivateKey == nil {
		return nil, ErrAuthorityUnavailable
	}
	tr := &http.Transport{TLSClientConfig:&tls.Config{
		MinVersion:tls.VersionTLS13, RootCAs:c.Roots.Clone(), Certificates:[]tls.Certificate{c.Certificate},
		VerifyConnection:func(s tls.ConnectionState) error {
			if s.Version != tls.VersionTLS13 || len(s.VerifiedChains)==0 || len(s.PeerCertificates)==0 {
				return ErrAuthorityUnavailable
			}
			leaf := s.PeerCertificates[0]
			now:=time.Now()
			if leaf==nil || leaf.IsCA || len(leaf.URIs)!=1 || leaf.URIs[0]==nil ||
				leaf.URIs[0].String()!=e.SPIFFEID || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
				leaf.KeyUsage&x509.KeyUsageDigitalSignature==0 {
				return ErrAuthorityUnavailable
			}
			for _, usage:=range leaf.ExtKeyUsage {
				if usage==x509.ExtKeyUsageServerAuth { return nil }
			}
			return ErrAuthorityUnavailable
		},
	},DisableKeepAlives:true}
	return &authorityClient{origin:e.Origin, client:&http.Client{Transport:tr,Timeout:5*time.Second,
		CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}},nil
}

func (c *authorityClient) read(ctx context.Context, method,path string, body []byte, max int) ([]byte,error) {
	req,err:=http.NewRequestWithContext(ctx,method,c.origin+path,bytes.NewReader(body))
	if err!=nil {return nil,ErrAuthorityUnavailable}
	if method==http.MethodPost {req.Header.Set("Content-Type","application/json")}
	req.GetBody=nil
	res,err:=c.client.Do(req)
	if err!=nil {return nil,ErrAuthorityUnavailable}
	defer res.Body.Close()
	if res.StatusCode==http.StatusForbidden || res.StatusCode==http.StatusUnauthorized {
		return nil,ErrAuthorityRejected
	}
	// Require the exact singleton response contract; Header.Get ignores
	// later field values and can hide conflicting cache/media declarations.
	cacheControl := res.Header.Values("Cache-Control")
	contentType := res.Header.Values("Content-Type")
	if res.StatusCode!=http.StatusOK || len(cacheControl)!=1 || cacheControl[0]!="no-store" ||
		len(contentType)!=1 || contentType[0]!="application/json" {
		return nil,ErrAuthorityUnavailable
	}
	raw,err:=io.ReadAll(io.LimitReader(res.Body,int64(max)+1))
	if err!=nil || len(raw)==0 || len(raw)>max {return nil,ErrAuthorityUnavailable}
	return raw,nil
}

type pinnedEvidenceSource struct {
	client *authorityClient
	scope EvidenceSourceScope
	key ed25519.PublicKey
}

// LiveAuthority composes actual independently authenticated sources. Every
// new decision checks current Runtime, fresh ACP, and each source's live
// revocation registry. It does not treat a previous proof as a grant.
type LiveAuthority struct {
	tenant string
	runtime, acp *authorityClient
	acpKey ed25519.PublicKey
	sources map[string]pinnedEvidenceSource
	// Private clock seam for deterministic freshness-boundary tests.
	now func() time.Time
}

func NewLiveAuthority(c LiveAuthorityConfig) (*LiveAuthority,error) {
	if !nameRe.MatchString(c.TenantID) || len(c.ACPKey)!=ed25519.PublicKeySize ||
		c.Runtime.SPIFFEID==c.ACP.SPIFFEID || c.Runtime.Origin==c.ACP.Origin ||
		len(c.Evidence)==0 || len(c.Evidence)>32 {
		return nil,ErrAuthorityUnavailable
	}
	runtime,err:=newAuthorityClient(c.Runtime,c.TLS)
	if err!=nil{return nil,err}
	acp,err:=newAuthorityClient(c.ACP,c.TLS)
	if err!=nil{return nil,err}
	a:= &LiveAuthority{tenant:c.TenantID,runtime:runtime,acp:acp,acpKey:bytes.Clone(c.ACPKey),sources:map[string]pinnedEvidenceSource{}}
	seen:=map[string]bool{c.Runtime.Origin:true,c.ACP.Origin:true}
	keyIDs:=map[string]bool{acpHash(c.ACPKey):true}
	peers:=map[string]bool{c.Runtime.SPIFFEID:true,c.ACP.SPIFFEID:true}
	for _,p:=range c.Evidence{
		if p.Scope.TenantID!=c.TenantID || !nameRe.MatchString(p.Scope.SourceID) ||
			len(p.PublicKey)!=ed25519.PublicKeySize || seen[p.Endpoint.Origin] ||
			peers[p.Endpoint.SPIFFEID] || keyIDs[acpHash(p.PublicKey)] {
			return nil,ErrAuthorityUnavailable
		}
		if _,exists:=a.sources[p.Scope.SourceID];exists{return nil,ErrAuthorityUnavailable}
		client,err:=newAuthorityClient(p.Endpoint,c.TLS)
		if err!=nil{return nil,err}
		a.sources[p.Scope.SourceID]=pinnedEvidenceSource{client:client,scope:p.Scope,key:bytes.Clone(p.PublicKey)}
		seen[p.Endpoint.Origin],peers[p.Endpoint.SPIFFEID],keyIDs[acpHash(p.PublicKey)]=true,true,true
	}
	return a,nil
}

func (a *LiveAuthority) currentRuntime(ctx context.Context,runID,invocation string)(RuntimeDecisionAuthority,error){
	var out RuntimeDecisionAuthority
	if a==nil || !acpUUID.MatchString(runID) || !acpUUID.MatchString(invocation){
		return out,ErrAuthorityRejected
	}
	raw,err:=a.runtime.read(ctx,http.MethodGet,"/internal/v1/decision-authority/"+runID+"?"+url.Values{"invocation_id":{invocation}}.Encode(),nil,8192)
	if err!=nil{return out,err}
	if !decodeACP(bytes.TrimSpace(raw),8192,&out,true) || !out.valid(a.tenant,runID,invocation){
		return RuntimeDecisionAuthority{},ErrAuthorityRejected
	}
	return out,nil
}

func (a *LiveAuthority) currentTime() time.Time {
	if a.now != nil {
		return a.now().UTC()
	}
	return time.Now().UTC()
}

func (a *LiveAuthority) build(ctx context.Context, runID, invocation string, evidence []EvidenceRef)(Principal,Request,error){
	return a.buildWithRuntime(ctx,runID,invocation,evidence,nil)
}

// A continuation must bind its entire authority read to the initial
// Runtime observation, not merely compare its outer before/after reads.
func (a *LiveAuthority) buildWithRuntime(ctx context.Context, runID, invocation string, evidence []EvidenceRef, expected *RuntimeDecisionAuthority)(Principal,Request,error){
	fail:=func(err error)(Principal,Request,error){return Principal{},Request{},err}
	if len(evidence)>32 || evidence==nil{return fail(ErrAuthorityRejected)}
	r,err:=a.currentRuntime(ctx,runID,invocation)
	if err!=nil{return fail(err)}
	if expected != nil && r != *expected {
		return fail(ErrAuthorityRejected)
	}
	query:=url.Values{"run_id":{r.RunID},"request_digest":{r.RequestDigest}}
	raw,err:=a.acp.read(ctx,http.MethodGet,"/internal/v1/decision-publication/"+r.RunIntentID+"?"+query.Encode(),nil,maxACPPublicationWire)
	if err!=nil{return fail(err)}
	now:=a.currentTime()
	p,err:=VerifyACPPublication(raw,a.acpKey,r.acpBinding(),now)
	if err!=nil{return fail(ErrAuthorityRejected)}
	input,err:=json.Marshal(p.Input)
	if err!=nil || "sha256:"+acpHash(input)!=r.InputDigest{return fail(ErrAuthorityRejected)}
	for _,e:=range evidence{
		source,ok:=a.sources[e.SourceID]
		if !ok || source.scope.RunID!=r.RunID || source.scope.AgentID!=r.AgentID ||
			source.scope.Service!=p.Input.Service || !evidenceScopeMatches(source.scope,e,now){
			return fail(ErrAuthorityRejected)
		}
		b,err:=json.Marshal(e)
		if err!=nil{return fail(ErrAuthorityRejected)}
		proof,err:=source.client.read(ctx,http.MethodPost,"/internal/v1/evidence:read",b,maxEvidenceWire)
		if err!=nil{return fail(err)}
		if VerifyEvidencePublication(proof,source.key,source.scope,e,a.currentTime())!=nil{
			return fail(ErrAuthorityRejected)
		}
	}
	// Recheck Runtime after reading all sources. This does not establish a
	// distributed atomic revocation fence; no protected effect is authorized.
	last,err:=a.currentRuntime(ctx,runID,invocation)
	if err!=nil{return fail(err)}
	if last!=r{return fail(ErrAuthorityRejected)}
	principal:=Principal{TenantID:r.TenantID,SubjectID:r.SubjectID,AgentID:r.AgentID,SessionID:r.SessionID,CallerID:"agent-runtime"}
	req:=Request{
		SchemaVersion:SchemaVersion, Identity:Identity{AgentID:r.AgentID,SessionID:r.SessionID,RunID:r.RunID},InvocationID:r.InvocationID,
		Input:p.Input, Constraints:Constraints{DeadlineMS:30000,MaxTokens:2048,MaxCostMicros:0,MaxCandidates:3},
		Versions:VersionSet{CapabilityCatalogVersion:p.CapabilitySnapshot.Version,StrategyVersion:PolicyVersion,PromptVersion:"none",ModelProfile:"rule-only"},
		ContextSnapshot:p.ContextSnapshot,CapabilitySnapshot:p.CapabilitySnapshot,Capabilities:p.Capabilities,
		Evidence:append([]EvidenceRef{},evidence...),
	}
	if principal.Validate()!=nil || req.Validate()!=nil{return fail(ErrAuthorityRejected)}
	if !a.inputsFreshAt(req, a.currentTime()) {
		return fail(ErrAuthorityRejected)
	}
	return principal,req,nil
}

// inputsFreshAt is shared by the final observation of both new turns and
// continuation receipts. It does not claim atomic distributed revocation.
func (a *LiveAuthority) inputsFreshAt(req Request, now time.Time) bool {
	if now.IsZero() {
		return false
	}
	for _, snapshot := range []SnapshotRef{req.ContextSnapshot, req.CapabilitySnapshot} {
		if now.Before(snapshot.IssuedAt) || !now.Before(snapshot.ExpiresAt) {
			return false
		}
	}
	for _, e := range req.Evidence {
		source, ok := a.sources[e.SourceID]
		if !ok || !evidenceScopeMatches(source.scope, e, now) {
			return false
		}
	}
	return true
}

// ResolveTurn only accepts reference selectors and Evidence claims. All
// other fields, including subject, task, capabilities and policy, originate
// from the two trusted owning services, never a Runtime caller's JSON.
func (a *LiveAuthority) ResolveTurn(ctx context.Context,runID,invocation string,evidence []EvidenceRef)(Principal,Request,error){
	return a.build(ctx,runID,invocation,evidence)
}

// VerifyDecisionInputs implements the existing Decision Core authority
// port. It re-fetches all sources and compares the entire generated request,
// including fixed bounded rule-only constraints. Replans remain denied.
func (a *LiveAuthority) VerifyDecisionInputs(ctx context.Context,p Principal,req Request)error{
	current,canonical,err:=a.build(ctx,req.Identity.RunID,req.InvocationID,req.Evidence)
	if err!=nil{return err}
	if p!=current || digest(req)!=digest(canonical){return ErrAuthorityRejected}
	return nil
}

var _ AuthorityVerifier = (*LiveAuthority)(nil)
