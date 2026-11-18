// Command ms-rbac-cat49-reviewer is not part of server startup or NATS/HTTP.
// It is default-off and may only be executed after separate operator approval.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/repository"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
)

const markerFile = "/run/cat49/ownership.json"

type ownership struct {
	Schema string `json:"schema"`
	Purpose string `json:"purpose"`
	RunID string `json:"run_id"`
	Project string `json:"project"`
	Network string `json:"network"`
	AuthDatabase string `json:"auth_database"`
	RBACDatabase string `json:"rbac_database"`
	RBACUser string `json:"rbac_user"`
	PostgresHost string `json:"postgres_host"`
	PostgresPort uint16 `json:"postgres_port"`
}

func (m ownership) valid() bool {
	run:=regexp.MustCompile("^cat49[a-z0-9]{5,20}$")
	database:=regexp.MustCompile("^cat49_[a-z0-9_]{4,60}$")
	user:=regexp.MustCompile("^[a-z][a-z0-9_]{1,60}$")
	return m.Schema=="cat49-disposable-ownership.v1" && m.Purpose=="cat49-reviewer" &&
		run.MatchString(m.RunID) && m.Project=="lp-v1-"+m.RunID &&
		m.Network==m.Project+"-net" && database.MatchString(m.AuthDatabase) &&
		database.MatchString(m.RBACDatabase) && m.AuthDatabase!=m.RBACDatabase &&
		user.MatchString(m.RBACUser) &&
		(m.PostgresHost=="127.0.0.1" || m.PostgresHost=="localhost") &&
		m.PostgresPort>0
}

func privateFile(path string,max int) ([]byte,error) {
	if !filepath.IsAbs(path) || filepath.Clean(path)!=path {return nil,errors.New("private path denied")}
	info,err:=os.Lstat(path)
	if err!=nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077!=0 ||
		info.Size()<=0 || info.Size()>int64(max) {return nil,errors.New("private file denied")}
	data,err:=os.ReadFile(path)
	if err!=nil || len(data)==0 || len(data)>max {return nil,errors.New("private file denied")}
	return data,nil
}
// Signing-key validation must happen before opening PostgreSQL or writing a role.
// A later signing error must not leave an unsigned privileged grant behind.
func grantSigningKeysReady(authKey, grantKey []byte) bool {
	return len(authKey) >= 32 && len(authKey) <= 4096 &&
		len(grantKey) >= 32 && len(grantKey) <= 4096 &&
		!bytes.Equal(authKey, grantKey)
}

func readMarker() (ownership,error) {
	var marker ownership
	raw,err:=privateFile(markerFile,4096)
	if err!=nil {return marker,err}
	if json.Unmarshal(raw,&marker)!=nil || !marker.valid() {return marker,errors.New("CAT49 owner marker denied")}
	return marker,nil
}
func execute() error {
	if os.Getenv("APP_ENV")!="cat49-disposable-operator" ||
		os.Getenv("RBAC_CAT49_REVIEWER_OPERATOR")!="enabled" {
		return errors.New("CAT49 operator disabled")
	}
	flags:=flag.NewFlagSet("ms-rbac-cat49-reviewer",flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestID:=flags.String("request-id","","independent grant operation UUID")
	operator:=flags.String("operator","","named operator")
	if flags.Parse(os.Args[1:])!=nil || flags.NArg()!=0 {
		return errors.New("CAT49 operator arguments denied")
	}
	marker,err:=readMarker()
	if err!=nil {return err}
	authKey,err:=privateFile(os.Getenv("RBAC_CAT49_AUTH_PROOF_KEY_FILE"),4096)
	if err!=nil {return err}
	grantKey,err:=privateFile(os.Getenv("RBAC_CAT49_GRANT_SIGNING_KEY_FILE"),4096)
	if err!=nil || !grantSigningKeysReady(authKey, grantKey) {return errors.New("CAT49 invalid or reused proof keys")}
	raw,err:=io.ReadAll(io.LimitReader(os.Stdin,4097))
	if err!=nil || len(raw)>4096 {return errors.New("CAT49 registration proof input denied")}
	proof,err:=usecase.VerifyCAT49Registration(raw,authKey,marker.RunID,marker.AuthDatabase)
	if err!=nil {return err}
	intent:=repository.CAT49ReviewerGrantIntent{RunID:marker.RunID,RequestID:*requestID,
		PrincipalID:proof.PrincipalID,AuthReceiptDigest:proof.ReceiptDigest,Operator:*operator}
	if usecase.ValidateCAT49ReviewerGrantIntent(intent)!=nil {return errors.New("CAT49 invalid operator intent")}
	dsn:=os.Getenv("RBAC_CAT49_REVIEWER_DSN")
	if dsn=="" {return errors.New("CAT49 private database config missing")}
	cfg,err:=pgxpool.ParseConfig(dsn)
	if err!=nil || cfg.ConnConfig.Database!=marker.RBACDatabase ||
		cfg.ConnConfig.User!=marker.RBACUser || cfg.ConnConfig.Host!=marker.PostgresHost ||
		cfg.ConnConfig.Port!=marker.PostgresPort || len(cfg.ConnConfig.Fallbacks)!=0 {
		return errors.New("CAT49 exact database connection denied")
	}
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
	defer cancel()
	pool,err:=pgxpool.NewWithConfig(ctx,cfg)
	if err!=nil {return errors.New("CAT49 DB unavailable")}
	defer pool.Close()
	var db,actor string
	var super bool
	if pool.QueryRow(ctx,"SELECT current_database(),current_user,(SELECT rolsuper FROM pg_roles WHERE rolname=current_user)").Scan(&db,&actor,&super)!=nil ||
		db!=marker.RBACDatabase || actor!=marker.RBACUser || super {
		return errors.New("CAT49 database identity denied")
	}
	result,err:=usecase.GrantCAT49Reviewer(ctx,repo.NewPrincipalRoleRepository(pool),intent)
	if err!=nil {return err}
	signed,err:=usecase.CAT49SignGrantReceipt(result,grantKey)
	if err!=nil {return err}
	return json.NewEncoder(os.Stdout).Encode(signed)
}
func main() {
	if err:=execute();err!=nil {
		// Do not leak DSN, incoming registration proof or cryptographic keys.
		fmt.Fprintln(os.Stderr,"CAT49 operator denied")
		os.Exit(1)
	}
}
