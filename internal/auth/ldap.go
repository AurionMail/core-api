package auth

import (
	"fmt"
	"strings"

	"aurion-api/internal/config"

	"github.com/go-ldap/ldap/v3"
)

type LDAPAuthenticator struct {
	cfg *config.Config
}

func NewLDAPAuthenticator(cfg *config.Config) *LDAPAuthenticator {
	return &LDAPAuthenticator{cfg: cfg}
}

// Authenticate attempts to bind user credentials directly against the LDAP server
func (a *LDAPAuthenticator) Authenticate(identifier, password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("empty password not allowed")
	}

	l, err := ldap.DialURL(a.cfg.LDAPURL)
	if err != nil {
		return "", fmt.Errorf("unable to reach LDAP server: %w", err)
	}
	defer l.Close()

	// Construct the User DN (Distinguished Name)
	// Example: mail=test2@aurion.io,ou=users,dc=aurion,dc=io
	userDN := fmt.Sprintf("%s=%s,%s", a.cfg.LDAPUserAttr, ldap.EscapeDN(identifier), a.cfg.LDAPBaseDN)

	// Attempt to bind using the provided password
	err = l.Bind(userDN, password)
	if err != nil {
		return "", fmt.Errorf("invalid LDAP credentials")
	}

	return identifier, nil
}

// ChangePassword verifies the current password and replaces it with newPassword
func (a *LDAPAuthenticator) ChangePassword(identifier, currentPassword, newPassword string) error {
	if strings.TrimSpace(currentPassword) == "" || strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("passwords cannot be empty")
	}

	l, err := ldap.DialURL(a.cfg.LDAPURL)
	if err != nil {
		return fmt.Errorf("unable to reach LDAP server: %w", err)
	}
	defer l.Close()

	// Construct the User DN
	userDN := fmt.Sprintf("%s=%s,%s", a.cfg.LDAPUserAttr, ldap.EscapeDN(identifier), a.cfg.LDAPBaseDN)

	// 1. Authenticate with current/temp password
	err = l.Bind(userDN, currentPassword)
	if err != nil {
		return fmt.Errorf("invalid LDAP credentials")
	}

	// 2. Prepare the password change operation
	modifyRequest := ldap.NewModifyRequest(userDN, nil)
	modifyRequest.Replace("userPassword", []string{newPassword})

	// 3. Execute the modification on LDAP
	err = l.Modify(modifyRequest)
	if err != nil {
		return fmt.Errorf("failed to update LDAP password: %w", err)
	}

	return nil
}
