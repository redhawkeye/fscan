package Plugins

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/shadow1ng/fscan/Common"
	"os/exec"
	"strconv"
	"strings"
)

type DomainInfo struct {
	conn   *ldap.Conn
	baseDN string
}

func (d *DomainInfo) Close() {
	if d.conn != nil {
		d.conn.Close()
	}
}

func (d *DomainInfo) GetCAComputers() ([]string, error) {
	Common.LogDebug("Starting to query CA servers in the domain...")

	searchRequest := ldap.NewSearchRequest(
		"CN=Configuration,"+d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=pKIEnrollmentService))",
		[]string{"cn", "dNSHostName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query CA servers: %v", err))
		return nil, err
	}

	var caComputers []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			caComputers = append(caComputers, cn)
			Common.LogDebug(fmt.Sprintf("Found CA server: %s", cn))
		}
	}

	if len(caComputers) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d CA servers", len(caComputers)))
	} else {
		Common.LogDebug("No CA servers found")
	}

	return caComputers, nil
}

func (d *DomainInfo) GetExchangeServers() ([]string, error) {
	Common.LogDebug("Starting to query Exchange servers...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=group)(cn=Exchange Servers))",
		[]string{"member"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query Exchange servers: %v", err))
		return nil, err
	}

	var exchangeServers []string
	for _, entry := range sr.Entries {
		for _, member := range entry.GetAttributeValues("member") {
			if member != "" {
				exchangeServers = append(exchangeServers, member)
				Common.LogDebug(fmt.Sprintf("Found Exchange server member: %s", member))
			}
		}
	}

	// Remove the first entry (if exists)
	if len(exchangeServers) > 1 {
		exchangeServers = exchangeServers[1:]
		Common.LogDebug("Removed the first entry")
	}

	if len(exchangeServers) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d Exchange servers", len(exchangeServers)))
	} else {
		Common.LogDebug("No Exchange servers found")
	}

	return exchangeServers, nil
}

func (d *DomainInfo) GetMsSqlServers() ([]string, error) {
	Common.LogDebug("Starting to query SQL Server servers...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(servicePrincipalName=MSSQLSvc*))",
		[]string{"name"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query SQL Server: %v", err))
		return nil, err
	}

	var sqlServers []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("name")
		if name != "" {
			sqlServers = append(sqlServers, name)
			Common.LogDebug(fmt.Sprintf("Found SQL Server: %s", name))
		}
	}

	if len(sqlServers) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d SQL Servers", len(sqlServers)))
	} else {
		Common.LogDebug("No SQL Servers found")
	}

	return sqlServers, nil
}

func (d *DomainInfo) GetSpecialComputers() (map[string][]string, error) {
	Common.LogDebug("Starting to query special computers...")
	results := make(map[string][]string)

	// Get SQL Server
	Common.LogDebug("Querying SQL Server...")
	sqlServers, err := d.GetMsSqlServers()
	if err == nil && len(sqlServers) > 0 {
		results["SQL Servers"] = sqlServers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("Error querying SQL Server: %v", err))
	}

	// Get CA servers
	Common.LogDebug("Querying CA servers...")
	caComputers, err := d.GetCAComputers()
	if err == nil && len(caComputers) > 0 {
		results["CA Servers"] = caComputers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("Error querying CA servers: %v", err))
	}

	// Get domain controllers
	Common.LogDebug("Querying domain controllers...")
	dcQuery := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"cn"},
		nil,
	)

	if sr, err := d.conn.SearchWithPaging(dcQuery, 10000); err == nil {
		var dcs []string
		for _, entry := range sr.Entries {
			name := entry.GetAttributeValue("cn")
			if name != "" {
				dcs = append(dcs, name)
				Common.LogDebug(fmt.Sprintf("Found domain controller: %s", name))
			}
		}
		if len(dcs) > 0 {
			results["Domain Controllers"] = dcs
			Common.LogSuccess(fmt.Sprintf("Found %d domain controllers", len(dcs)))
		} else {
			Common.LogDebug("No domain controllers found")
		}
	} else {
		Common.LogError(fmt.Sprintf("Error querying domain controllers: %v", err))
	}

	// Get Exchange servers
	Common.LogDebug("Querying Exchange servers...")
	exchangeServers, err := d.GetExchangeServers()
	if err == nil && len(exchangeServers) > 0 {
		results["Exchange Servers"] = exchangeServers
	} else if err != nil {
		Common.LogError(fmt.Sprintf("Error querying Exchange servers: %v", err))
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("Special computer query completed, found %d types of servers", len(results)))
		for serverType, servers := range results {
			Common.LogDebug(fmt.Sprintf("%s: %d", serverType, len(servers)))
		}
	} else {
		Common.LogDebug("No special computers found")
	}

	return results, nil
}

func (d *DomainInfo) GetDomainUsers() ([]string, error) {
	Common.LogDebug("Starting to query domain users...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query domain users: %v", err))
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		username := entry.GetAttributeValue("sAMAccountName")
		if username != "" {
			users = append(users, username)
			Common.LogDebug(fmt.Sprintf("Found user: %s", username))
		}
	}

	if len(users) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d domain users", len(users)))
	} else {
		Common.LogDebug("No domain users found")
	}

	return users, nil
}

func (d *DomainInfo) GetDomainAdmins() ([]string, error) {
	Common.LogDebug("Starting to query domain admins...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=group)(cn=Domain Admins))",
		[]string{"member", "sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query Domain Admins group: %v", err))
		return nil, err
	}

	var admins []string
	if len(sr.Entries) > 0 {
		members := sr.Entries[0].GetAttributeValues("member")
		Common.LogDebug(fmt.Sprintf("Found %d Domain Admins group members", len(members)))

		for _, memberDN := range members {
			memberSearch := ldap.NewSearchRequest(
				memberDN,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"sAMAccountName"},
				nil,
			)

			memberResult, err := d.conn.Search(memberSearch)
			if err != nil {
				Common.LogError(fmt.Sprintf("Failed to query member %s: %v", memberDN, err))
				continue
			}

			if len(memberResult.Entries) > 0 {
				samAccountName := memberResult.Entries[0].GetAttributeValue("sAMAccountName")
				if samAccountName != "" {
					admins = append(admins, samAccountName)
					Common.LogDebug(fmt.Sprintf("Found domain admin: %s", samAccountName))
				}
			}
		}
	}

	if len(admins) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d domain admins", len(admins)))
	} else {
		Common.LogDebug("No domain admins found")
	}

	return admins, nil
}

func (d *DomainInfo) GetOUs() ([]string, error) {
	Common.LogDebug("Starting to query organizational units (OUs)...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=organizationalUnit)",
		[]string{"ou"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query OUs: %v", err))
		return nil, err
	}

	var ous []string
	for _, entry := range sr.Entries {
		ou := entry.GetAttributeValue("ou")
		if ou != "" {
			ous = append(ous, ou)
			Common.LogDebug(fmt.Sprintf("Found OU: %s", ou))
		}
	}

	if len(ous) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d organizational units", len(ous)))
	} else {
		Common.LogDebug("No organizational units found")
	}

	return ous, nil
}

func (d *DomainInfo) GetComputers() ([]Computer, error) {
	Common.LogDebug("Starting to query domain computers...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=computer))",
		[]string{"cn", "operatingSystem", "dNSHostName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query computers: %v", err))
		return nil, err
	}

	var computers []Computer
	for _, entry := range sr.Entries {
		computer := Computer{
			Name:            entry.GetAttributeValue("cn"),
			OperatingSystem: entry.GetAttributeValue("operatingSystem"),
			DNSHostName:     entry.GetAttributeValue("dNSHostName"),
		}
		computers = append(computers, computer)
		Common.LogDebug(fmt.Sprintf("Found computer: %s (OS: %s, DNS: %s)",
			computer.Name,
			computer.OperatingSystem,
			computer.DNSHostName))
	}

	if len(computers) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d computers", len(computers)))

		// Count operating system distribution
		osCount := make(map[string]int)
		for _, computer := range computers {
			if computer.OperatingSystem != "" {
				osCount[computer.OperatingSystem]++
			}
		}

		for os, count := range osCount {
			Common.LogDebug(fmt.Sprintf("Operating System %s: %d", os, count))
		}
	} else {
		Common.LogDebug("No computers found")
	}

	return computers, nil
}

// Define computer struct
type Computer struct {
	Name            string
	OperatingSystem string
	DNSHostName     string
}

func (d *DomainInfo) GetTrustDomains() ([]string, error) {
	Common.LogDebug("Starting to query domain trust relationships...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=trustedDomain))",
		[]string{"cn", "trustDirection", "trustType"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query trusted domains: %v", err))
		return nil, err
	}

	var trustInfo []string
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		if cn != "" {
			trustInfo = append(trustInfo, cn)
			Common.LogDebug(fmt.Sprintf("Found trusted domain: %s", cn))
		}
	}

	if len(trustInfo) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d trusted domains", len(trustInfo)))
	} else {
		Common.LogDebug("No trusted domains found")
	}

	return trustInfo, nil
}

func (d *DomainInfo) GetAdminGroups() (map[string][]string, error) {
	Common.LogDebug("Starting to query admin group information...")

	adminGroups := map[string]string{
		"Domain Admins":     "(&(objectClass=group)(cn=Domain Admins))",
		"Enterprise Admins": "(&(objectClass=group)(cn=Enterprise Admins))",
		"Administrators":    "(&(objectClass=group)(cn=Administrators))",
	}

	results := make(map[string][]string)

	for groupName, filter := range adminGroups {
		Common.LogDebug(fmt.Sprintf("Querying %s group...", groupName))

		searchRequest := ldap.NewSearchRequest(
			d.baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"member"},
			nil,
		)

		sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
		if err != nil {
			Common.LogError(fmt.Sprintf("Failed to query %s group: %v", groupName, err))
			continue
		}

		if len(sr.Entries) > 0 {
			members := sr.Entries[0].GetAttributeValues("member")
			if len(members) > 0 {
				results[groupName] = members
				Common.LogDebug(fmt.Sprintf("%s group member count: %d", groupName, len(members)))
				for _, member := range members {
					Common.LogDebug(fmt.Sprintf("- %s: %s", groupName, member))
				}
			} else {
				Common.LogDebug(fmt.Sprintf("No members found in %s group", groupName))
			}
		}
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d admin groups", len(results)))
	} else {
		Common.LogDebug("No admin group information found")
	}

	return results, nil
}

func (d *DomainInfo) GetDelegation() (map[string][]string, error) {
	Common.LogDebug("Starting to query delegation information...")

	delegationQueries := map[string]string{
		"Unconstrained Delegation":     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		"Constrained Delegation":      "(msDS-AllowedToDelegateTo=*)",
		"Resource-Based Constrained Delegation": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
	}

	results := make(map[string][]string)

	for delegationType, query := range delegationQueries {
		Common.LogDebug(fmt.Sprintf("Querying %s...", delegationType))

		searchRequest := ldap.NewSearchRequest(
			d.baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			query,
			[]string{"cn", "distinguishedName"},
			nil,
		)

		sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
		if err != nil {
			Common.LogError(fmt.Sprintf("Failed to query %s: %v", delegationType, err))
			continue
		}

		var entries []string
		for _, entry := range sr.Entries {
			cn := entry.GetAttributeValue("cn")
			if cn != "" {
				entries = append(entries, cn)
				Common.LogDebug(fmt.Sprintf("Found %s: %s", delegationType, cn))
			}
		}

		if len(entries) > 0 {
			results[delegationType] = entries
			Common.LogSuccess(fmt.Sprintf("%s: Found %d records", delegationType, len(entries)))
		} else {
			Common.LogDebug(fmt.Sprintf("No %s records found", delegationType))
		}
	}

	if len(results) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d types of delegation configurations", len(results)))
	} else {
		Common.LogDebug("No delegation configurations found")
	}

	return results, nil
}

// Get AS-REP Roasting vulnerability users
func (d *DomainInfo) GetAsrepRoastUsers() ([]string, error) {
	Common.LogDebug("Starting to query AS-REP Roasting vulnerability users...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query AS-REP Roasting vulnerability users: %v", err))
		return nil, err
	}

	var users []string
	for _, entry := range sr.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		if name != "" {
			users = append(users, name)
			Common.LogDebug(fmt.Sprintf("Found user with AS-REP Roasting vulnerability: %s", name))
		}
	}

	if len(users) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d users with AS-REP Roasting vulnerability", len(users)))
	} else {
		Common.LogDebug("No users with AS-REP Roasting vulnerability found")
	}

	return users, nil
}

func (d *DomainInfo) GetPasswordPolicy() (map[string]string, error) {
	Common.LogDebug("Starting to query domain password policy...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"maxPwdAge",
			"minPwdAge",
			"minPwdLength",
			"pwdHistoryLength",
			"pwdProperties",
			"lockoutThreshold",
			"lockoutDuration",
		},
		nil,
	)

	sr, err := d.conn.Search(searchRequest)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query password policy: %v", err))
		return nil, err
	}

	if len(sr.Entries) == 0 {
		Common.LogError("No password policy information found")
		return nil, fmt.Errorf("No password policy information found")
	}

	policy := make(map[string]string)
	entry := sr.Entries[0]

	// Convert max password age
	if maxAge := entry.GetAttributeValue("maxPwdAge"); maxAge != "" {
		maxAgeInt, _ := strconv.ParseInt(maxAge, 10, 64)
		if maxAgeInt != 0 {
			days := float64(maxAgeInt) * -1 / float64(864000000000)
			policy["Max Password Age"] = fmt.Sprintf("%.0f days", days)
			Common.LogDebug(fmt.Sprintf("Max Password Age: %.0f days", days))
		}
	}

	if minLength := entry.GetAttributeValue("minPwdLength"); minLength != "" {
		policy["Min Password Length"] = minLength + " characters"
		Common.LogDebug(fmt.Sprintf("Min Password Length: %s characters", minLength))
	}

	if historyLength := entry.GetAttributeValue("pwdHistoryLength"); historyLength != "" {
		policy["Password History Length"] = historyLength + " entries"
		Common.LogDebug(fmt.Sprintf("Password History Length: %s entries", historyLength))
	}

	if lockoutThreshold := entry.GetAttributeValue("lockoutThreshold"); lockoutThreshold != "" {
		policy["Account Lockout Threshold"] = lockoutThreshold + " attempts"
		Common.LogDebug(fmt.Sprintf("Account Lockout Threshold: %s attempts", lockoutThreshold))
	}

	if len(policy) > 0 {
		Common.LogSuccess(fmt.Sprintf("Successfully retrieved domain password policy with %d configurations", len(policy)))

		// Security assessment
		minLengthInt, _ := strconv.Atoi(strings.TrimSuffix(policy["Min Password Length"], " characters"))
		if minLengthInt < 8 {
			Common.LogDebug("Warning: Minimum password length is less than 8 characters, which poses a security risk")
		}

		lockoutThresholdInt, _ := strconv.Atoi(strings.TrimSuffix(policy["Account Lockout Threshold"], " attempts"))
		if lockoutThresholdInt == 0 {
			Common.LogDebug("Warning: Account lockout policy is not enabled, which poses a brute force attack risk")
		}
	} else {
		Common.LogDebug("No password policy configurations found")
	}

	return policy, nil
}

func (d *DomainInfo) GetSPNs() (map[string][]string, error) {
	Common.LogDebug("Starting to query SPN information...")

	searchRequest := ldap.NewSearchRequest(
		d.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(servicePrincipalName=*)",
		[]string{"distinguishedName", "servicePrincipalName", "cn"},
		nil,
	)

	sr, err := d.conn.SearchWithPaging(searchRequest, 10000)
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to query SPNs: %v", err))
		return nil, err
	}

	spns := make(map[string][]string)
	for _, entry := range sr.Entries {
		dn := entry.GetAttributeValue("distinguishedName")
		cn := entry.GetAttributeValue("cn")
		spnList := entry.GetAttributeValues("servicePrincipalName")

		if len(spnList) > 0 {
			key := fmt.Sprintf("SPN: %s", dn)
			spns[key] = spnList
			Common.LogDebug(fmt.Sprintf("Found SPN - CN: %s", cn))
			for _, spn := range spnList {
				Common.LogDebug(fmt.Sprintf("  - %s", spn))
			}
		}
	}

	if len(spns) > 0 {
		Common.LogSuccess(fmt.Sprintf("Found %d SPN configurations", len(spns)))
	} else {
		Common.LogDebug("No SPN configurations found")
	}

	return spns, nil
}

func getDomainController() (string, error) {
	Common.LogDebug("Starting to query domain controller address...")

	// Attempt to get the current domain name using wmic
	Common.LogDebug("Using wmic to get domain name...")
	cmd := exec.Command("wmic", "computersystem", "get", "domain")
	output, err := cmd.Output()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get domain name: %v", err))
		return "", fmt.Errorf("Failed to get domain name: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		Common.LogError("wmic output format is abnormal, domain name not found")
		return "", fmt.Errorf("Domain name not found")
	}

	domain := strings.TrimSpace(lines[1])
	if domain == "" {
		Common.LogError("Retrieved domain name is empty")
		return "", fmt.Errorf("Domain name is empty")
	}
	Common.LogDebug(fmt.Sprintf("Retrieved domain name: %s", domain))

	// Use nslookup to query the domain controller
	Common.LogDebug(fmt.Sprintf("Using nslookup to query domain controller (_ldap._tcp.dc._msdcs.%s)...", domain))
	cmd = exec.Command("nslookup", "-type=SRV", fmt.Sprintf("_ldap._tcp.dc._msdcs.%s", domain))
	output, err = cmd.Output()
	if err != nil {
		Common.LogError(fmt.Sprintf("nslookup query failed: %v", err))
		return "", fmt.Errorf("Failed to query domain controller: %v", err)
	}

	// Parse nslookup output
	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "svr hostname") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				dcHost := strings.TrimSpace(parts[1])
				dcHost = strings.TrimSuffix(dcHost, ".")
				Common.LogSuccess(fmt.Sprintf("Found domain controller: %s", dcHost))
				return dcHost, nil
			}
		}
	}

	// Attempt to use domain prefix with DC suffix
	Common.LogDebug("No domain controller found from nslookup, attempting to use domain prefix...")
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 0 {
		dcHost := fmt.Sprintf("dc.%s", domain)
		Common.LogDebug(fmt.Sprintf("Using alternative domain controller address: %s", dcHost))
		return dcHost, nil
	}

	Common.LogError("Unable to get domain controller address")
	return "", fmt.Errorf("Unable to get domain controller address")
}

func NewDomainInfo() (*DomainInfo, error) {
	Common.LogDebug("Starting to initialize domain information...")

	// Get domain controller address
	Common.LogDebug("Getting domain controller address...")
	dcHost, err := getDomainController()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get domain controller: %v", err))
		return nil, fmt.Errorf("Failed to get domain controller: %v", err)
	}
	Common.LogDebug(fmt.Sprintf("Successfully retrieved domain controller address: %s", dcHost))

	// Create SSPI client
	Common.LogDebug("Creating SSPI client...")
	ldapClient, err := gssapi.NewSSPIClient()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to create SSPI client: %v", err))
		return nil, fmt.Errorf("Failed to create SSPI client: %v", err)
	}
	defer ldapClient.Close()
	Common.LogDebug("SSPI client created successfully")

	// Create LDAP connection
	Common.LogDebug(fmt.Sprintf("Connecting to LDAP server ldap://%s:389", dcHost))
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcHost))
	if err != nil {
		Common.LogError(fmt.Sprintf("LDAP connection failed: %v", err))
		return nil, fmt.Errorf("LDAP connection failed: %v", err)
	}
	Common.LogDebug("LDAP connection established successfully")

	// Perform GSSAPI bind
	Common.LogDebug(fmt.Sprintf("Performing GSSAPI bind (ldap/%s)...", dcHost))
	err = conn.GSSAPIBind(ldapClient, fmt.Sprintf("ldap/%s", dcHost), "")
	if err != nil {
		conn.Close()
		Common.LogError(fmt.Sprintf("GSSAPI bind failed: %v", err))
		return nil, fmt.Errorf("GSSAPI bind failed: %v", err)
	}
	Common.LogDebug("GSSAPI bind successful")

	// Get defaultNamingContext
	Common.LogDebug("Querying defaultNamingContext...")
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		conn.Close()
		Common.LogError(fmt.Sprintf("Failed to get defaultNamingContext: %v", err))
		return nil, fmt.Errorf("Failed to get defaultNamingContext: %v", err)
	}

	if len(result.Entries) == 0 {
		conn.Close()
		Common.LogError("No defaultNamingContext found")
		return nil, fmt.Errorf("No defaultNamingContext found")
	}

	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		Common.LogDebug("defaultNamingContext is empty, using alternative method to get BaseDN")
		baseDN = getDomainDN(dcHost) // Use alternative method
	}

	Common.LogSuccess(fmt.Sprintf("Initialization completed, using BaseDN: %s", baseDN))

	return &DomainInfo{
		conn:   conn,
		baseDN: baseDN,
	}, nil
}

func DCInfoScan(info *Common.HostInfo) (err error) {

	// Create DomainInfo instance
	Common.LogDebug("Initializing domain information...")
	di, err := NewDomainInfo()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to initialize domain information: %v", err))
		return err
	}
	defer di.Close()

	// Get special computers list
	specialComputers, err := di.GetSpecialComputers()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get special computers: %v", err))
	} else {
		categories := []string{
			"SQL Servers",
			"CA Servers",
			"Domain Controllers",
			"Exchange Servers",
		}

		Common.LogSuccess("[*] Special computer information:")
		for _, category := range categories {
			if computers, ok := specialComputers[category]; ok {
				Common.LogSuccess(fmt.Sprintf("[+] %s:", category))
				for _, computer := range computers {
					Common.LogSuccess(fmt.Sprintf("    %s", computer))
				}
			}
		}
	}

	// Get domain users
	users, err := di.GetDomainUsers()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get domain users: %v", err))
	} else {
		Common.LogSuccess("[*] Domain user list:")
		for _, user := range users {
			Common.LogSuccess(fmt.Sprintf("    %s", user))
		}
	}

	// Get domain admins
	admins, err := di.GetDomainAdmins()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get domain admins: %v", err))
	} else {
		Common.LogSuccess("[*] Domain admin list:")
		for _, admin := range admins {
			Common.LogSuccess(fmt.Sprintf("    %s", admin))
		}
	}

	// Get organizational units
	ous, err := di.GetOUs()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get organizational units: %v", err))
	} else {
		Common.LogSuccess("[*] Organizational units:")
		for _, ou := range ous {
			Common.LogSuccess(fmt.Sprintf("    %s", ou))
		}
	}

	// Get domain computers
	computers, err := di.GetComputers()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get domain computers: %v", err))
	} else {
		Common.LogSuccess("[*] Domain computers:")
		for _, computer := range computers {
			if computer.OperatingSystem != "" {
				Common.LogSuccess(fmt.Sprintf("    %s --> %s", computer.Name, computer.OperatingSystem))
			} else {
				Common.LogSuccess(fmt.Sprintf("    %s", computer.Name))
			}
		}
	}

	// Get trust domain relationships
	trustDomains, err := di.GetTrustDomains()
	if err == nil && len(trustDomains) > 0 {
		Common.LogSuccess("[*] Trust domain relationships:")
		for _, domain := range trustDomains {
			Common.LogSuccess(fmt.Sprintf("    %s", domain))
		}
	}

	// Get domain admin group information
	adminGroups, err := di.GetAdminGroups()
	if err == nil && len(adminGroups) > 0 {
		Common.LogSuccess("[*] Admin group information:")
		for groupName, members := range adminGroups {
			Common.LogSuccess(fmt.Sprintf("[+] %s members:", groupName))
			for _, member := range members {
				Common.LogSuccess(fmt.Sprintf("    %s", member))
			}
		}
	}

	// Get delegation information
	delegations, err := di.GetDelegation()
	if err == nil && len(delegations) > 0 {
		Common.LogSuccess("[*] Delegation information:")
		for delegationType, entries := range delegations {
			Common.LogSuccess(fmt.Sprintf("[+] %s:", delegationType))
			for _, entry := range entries {
				Common.LogSuccess(fmt.Sprintf("    %s", entry))
			}
		}
	}

	// Get AS-REP Roasting vulnerability users
	asrepUsers, err := di.GetAsrepRoastUsers()
	if err == nil && len(asrepUsers) > 0 {
		Common.LogSuccess("[*] AS-REP weak password accounts:")
		for _, user := range asrepUsers {
			Common.LogSuccess(fmt.Sprintf("    %s", user))
		}
	}

	// Get domain password policy
	passwordPolicy, err := di.GetPasswordPolicy()
	if err == nil && len(passwordPolicy) > 0 {
		Common.LogSuccess("[*] Domain password policy:")
		for key, value := range passwordPolicy {
			Common.LogSuccess(fmt.Sprintf("    %s: %s", key, value))
		}
	}

	// Get SPN information
	spns, err := di.GetSPNs()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get SPN information: %v", err))
	} else if len(spns) > 0 {
		Common.LogSuccess("[*] SPN information:")
		for dn, spnList := range spns {
			Common.LogSuccess(fmt.Sprintf("[+] %s", dn))
			for _, spn := range spnList {
				Common.LogSuccess(fmt.Sprintf("    %s", spn))
			}
		}
	}

	return nil
}

// Helper function: Get domain DN from server address
func getDomainDN(server string) string {
	parts := strings.Split(server, ".")
	var dn []string
	for _, part := range parts {
		dn = append(dn, fmt.Sprintf("DC=%s", part))
	}
	return strings.Join(dn, ",")
}
