"""Transport security, sensitive-file exposures, and infrastructure probes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .models import Response
from .payloads import GRAPHQL_QUERY, host_probe, make_token, similarity
from .registry import SCOPE_TARGET, SOURCE_ACTIVE, SOURCE_PASSIVE, CheckContext, register

Matcher = Callable[[Response], str | None]


# ------------------------------------------------------------------ matchers
def _rx(pattern: str, label: str, *, mask: bool = False) -> Matcher:
    compiled = re.compile(pattern, re.I | re.S)

    def matcher(response: Response) -> str | None:
        match = compiled.search((response.text or "")[:500000])
        if not match:
            return None
        if mask:
            return label
        return f"{label}: {match.group(0)[:140]}"

    return matcher


def _all(*needles: str, label: str = "content signature") -> Matcher:
    lowered = [needle.lower() for needle in needles]

    def matcher(response: Response) -> str | None:
        text = (response.text or "")[:500000].lower()
        if all(needle in text for needle in lowered):
            return f"{label}: " + ", ".join(needles)
        return None

    return matcher


def _magic(magic: bytes, label: str) -> Matcher:
    def matcher(response: Response) -> str | None:
        blob = response.body or b""
        if blob.startswith(magic) or magic in blob[:600]:
            return f"{label} signature detected"
        return None

    return matcher


def _env_matcher(response: Response) -> str | None:
    lines = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]{1,64})=(.*)$", (response.text or "")[:300000])
    keys = [name for name, _ in lines]
    if len(keys) < 2:
        return None
    sensitive = [
        key
        for key in keys
        if re.search(r"(?i)(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE|AWS|DATABASE|DB_)", key)
    ]
    if not sensitive and len(keys) < 4:
        return None
    shown = ", ".join(sorted(set(sensitive or keys))[:8])
    return f"Environment variable names exposed: {shown}"


def _config_keys(keys: tuple[str, ...], label: str) -> Matcher:
    pattern = re.compile("|".join(re.escape(key) for key in keys), re.I)

    def matcher(response: Response) -> str | None:
        text = (response.text or "")[:300000]
        found = sorted({match.group(0) for match in pattern.finditer(text)}, key=str.lower)
        if not found:
            return None
        if "{" not in text and ":" not in text:
            return None
        return f"{label}: {', '.join(found[:6])}"

    return matcher


def _sql_dump(response: Response) -> str | None:
    match = re.search(r"(INSERT INTO|CREATE TABLE|-- (?:MySQL|PostgreSQL) .*?dump|DROP TABLE)", response.text or "", re.I)
    if not match:
        return None
    return f"SQL dump signature: {match.group(0)[:80]}"


def _admin_panel(response: Response) -> str | None:
    text = (response.text or "").lower()
    has_password = 'type="password"' in text or "type='password'" in text
    if has_password and re.search(r"admin|login|sign in|dashboard", text):
        return "Password-protected admin/login interface detected"
    return None


def _directory_listing(response: Response) -> str | None:
    text = (response.text or "").lower()
    if "<title>index of" in text or "directory listing for" in text or "index of /" in text:
        return "Directory index listing detected"
    return None


# --------------------------------------------------------------- path registry
@dataclass(frozen=True)
class PathSpec:
    check_id: str
    title: str
    path: str
    severity: str
    category: str
    matcher: Matcher
    cwe: str
    remediation: str
    description: str = ""


PATHS: list[PathSpec] = [
    PathSpec("AEG-EXP-001", "Exposed Git HEAD", "/.git/HEAD", "high", "Exposures",
             _rx(r"(?m)^(ref:\s+refs/[^\r\n]+|[0-9a-f]{40})", "Git ref"), "CWE-538",
             "Block /.git/ at the edge and remove VCS metadata from web roots."),
    PathSpec("AEG-EXP-002", "Exposed Git config", "/.git/config", "high", "Exposures",
             _all("[core]", label="Git configuration"), "CWE-538",
             "Block /.git/ and rotate any credentials referenced by the repository."),
    PathSpec("AEG-EXP-003", "Exposed Git reflog", "/.git/logs/HEAD", "high", "Exposures",
             _rx(r"\b[0-9a-f]{40}\b", "Git reflog entry"), "CWE-538",
             "Block /.git/ and remove repository metadata from production."),
    PathSpec("AEG-EXP-004", "Exposed Git index", "/.git/index", "high", "Exposures",
             _magic(b"DIRC", "Git index"), "CWE-538",
             "Block /.git/ and remove repository metadata from production."),
    PathSpec("AEG-EXP-005", "Exposed Git credential store", "/.git-credentials", "critical", "Exposures",
             _all("https://", label="Git credential store"), "CWE-798",
             "Delete the file, block dotfiles, and rotate exposed credentials."),
    PathSpec("AEG-EXP-006", "Exposed Subversion metadata", "/.svn/entries", "medium", "Exposures",
             _rx(r"(?m)^(?:dir|file)$|wc-entries|svn://", "Subversion metadata"), "CWE-538",
             "Block /.svn/ and remove VCS metadata from web roots."),
    PathSpec("AEG-EXP-007", "Exposed .env file", "/.env", "critical", "Exposures",
             _env_matcher, "CWE-538",
             "Block dotfiles, remove .env from the web root, and rotate all contained secrets."),
    PathSpec("AEG-EXP-008", "Exposed .env.local file", "/.env.local", "critical", "Exposures",
             _env_matcher, "CWE-538",
             "Block dotfiles and rotate any secrets stored in local environment files."),
    PathSpec("AEG-EXP-009", "Exposed .env.production file", "/.env.production", "critical", "Exposures",
             _env_matcher, "CWE-538",
             "Remove production environment files from the web root and rotate secrets."),
    PathSpec("AEG-EXP-010", "Exposed .env.staging file", "/.env.staging", "critical", "Exposures",
             _env_matcher, "CWE-538",
             "Remove staging environment files from the web root and rotate secrets."),
    PathSpec("AEG-EXP-011", "Exposed .env backup", "/.env.bak", "critical", "Exposures",
             _env_matcher, "CWE-538",
             "Delete backup environment files and rotate all exposed credentials."),
    PathSpec("AEG-EXP-012", "Exposed macOS .DS_Store", "/.DS_Store", "low", "Exposures",
             _magic(b"Bud1", "DS_Store"), "CWE-538",
             "Block .DS_Store files from deployment artifacts."),
    PathSpec("AEG-EXP-013", "Exposed SSH private key", "/id_rsa", "critical", "Exposures",
             _rx(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "Private key"), "CWE-321",
             "Remove the key, block dotfiles, and rotate the compromised key pair."),
    PathSpec("AEG-EXP-014", "Exposed SSH key under .ssh", "/.ssh/id_rsa", "critical", "Exposures",
             _rx(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "Private key"), "CWE-321",
             "Block /.ssh/, remove the key, and rotate the key pair."),
    PathSpec("AEG-EXP-015", "Exposed AWS credentials", "/.aws/credentials", "critical", "Exposures",
             _config_keys(("aws_access_key_id", "aws_secret_access_key", "session_token"), "AWS credential keys"), "CWE-798",
             "Remove the file, block dotfiles, and rotate/disable the exposed keys."),
    PathSpec("AEG-EXP-016", "Exposed AWS profile configuration", "/.aws/config", "low", "Exposures",
             _config_keys(("region", "output", "profile", "role_arn"), "AWS profile configuration"), "CWE-538",
             "Block .aws configuration files from the web root."),
    PathSpec("AEG-EXP-017", "Exposed Kubernetes config", "/.kube/config", "critical", "Exposures",
             _all("clusters:", "users:", label="Kubernetes kubeconfig"), "CWE-538",
             "Remove the kubeconfig, block dotfiles, and rotate cluster credentials."),
    PathSpec("AEG-EXP-018", "Exposed npm authentication token", "/.npmrc", "critical", "Exposures",
             _rx(r"_authToken|//registry\.", "npm registry token"), "CWE-798",
             "Remove .npmrc from the web root and revoke the npm token."),
    PathSpec("AEG-EXP-019", "Exposed PyPI credentials", "/.pypirc", "high", "Exposures",
             _all("[pypi]", label="PyPI configuration"), "CWE-798",
             "Remove .pypirc and rotate repository credentials."),
    PathSpec("AEG-EXP-020", "Exposed .netrc credentials", "/.netrc", "high", "Exposures",
             _rx(r"(?m)^\s*machine\s+\S+", "netrc machine entry"), "CWE-798",
             "Remove .netrc from the web root and rotate stored credentials."),
    PathSpec("AEG-EXP-021", "Exposed Docker registry credentials", "/.docker/config.json", "high", "Exposures",
             _config_keys(("auths", "credsStore", "credHelpers"), "Docker credential configuration"), "CWE-798",
             "Remove the Docker config from the web root and rotate registry credentials."),
    PathSpec("AEG-EXP-022", "Exposed bash history", "/.bash_history", "high", "Exposures",
             _rx(r"(?m)^(?:sudo|ssh|scp|mysql|psql|docker|kubectl|aws|curl|wget|export)\s", "Shell history command"), "CWE-538",
             "Block dotfiles and prevent shell history from being deployed."),
    PathSpec("AEG-EXP-023", "Exposed zsh history", "/.zsh_history", "high", "Exposures",
             _rx(r"(?m)^(?:sudo|ssh|scp|mysql|psql|docker|kubectl|aws|curl|wget|export)\s", "Shell history command"), "CWE-538",
             "Block dotfiles and prevent shell history from being deployed."),
    PathSpec("AEG-EXP-024", "Exposed MySQL history", "/.mysql_history", "high", "Exposures",
             _rx(r"(?i)\b(select|insert|update|delete|create|alter)\b", "SQL history statement"), "CWE-538",
             "Block dotfiles and prevent database client history from being deployed."),
    PathSpec("AEG-EXP-025", "Exposed PostgreSQL password file", "/.pgpass", "critical", "Exposures",
             _rx(r"(?m)^[^:\r\n]+:[^:\r\n]+:[^:\r\n]+:[^:\r\n]+:.+$", "pgpass entry"), "CWE-798",
             "Remove .pgpass and rotate database credentials."),
    PathSpec("AEG-EXP-026", "Exposed htpasswd file", "/.htpasswd", "critical", "Exposures",
             _rx(r":\$(?:apr1|2[aby]|5|6)\$|:\{SHA\}", "Password hash"), "CWE-538",
             "Block dotfiles, remove .htpasswd from the web root, and rotate passwords."),
    PathSpec("AEG-EXP-027", "Exposed Terraform state", "/terraform.tfstate", "critical", "Exposures",
             _all('"terraform_version"', '"resources"', label="Terraform state"), "CWE-538",
             "Store state in a protected backend; remove it from the web root and rotate secrets."),
    PathSpec("AEG-EXP-028", "Exposed backup archive (ZIP)", "/backup.zip", "high", "Exposures",
             _magic(b"PK\x03\x04", "ZIP archive"), "CWE-538",
             "Remove backups from the web root and store them in access-controlled storage."),
    PathSpec("AEG-EXP-029", "Exposed backup archive (TAR)", "/backup.tar", "high", "Exposures",
             _magic(b"ustar", "TAR archive"), "CWE-538",
             "Remove backups from the web root and store them in access-controlled storage."),
    PathSpec("AEG-EXP-030", "Exposed backup archive (tar.gz)", "/backup.tar.gz", "high", "Exposures",
             _magic(b"\x1f\x8b", "GZIP archive"), "CWE-538",
             "Remove backups from the web root and store them in access-controlled storage."),
    PathSpec("AEG-EXP-031", "Exposed backup archive (RAR)", "/backup.rar", "high", "Exposures",
             _magic(b"Rar!\x1a\x07", "RAR archive"), "CWE-538",
             "Remove backups from the web root and store them in access-controlled storage."),
    PathSpec("AEG-EXP-032", "Exposed SQL backup", "/backup.sql", "critical", "Exposures",
             _sql_dump, "CWE-538",
             "Remove SQL dumps from the web root and rotate any contained credentials."),
    PathSpec("AEG-EXP-033", "Exposed database dump", "/database.sql", "critical", "Exposures",
             _sql_dump, "CWE-538",
             "Remove database dumps from the web root and rotate credentials."),
    PathSpec("AEG-EXP-034", "Exposed database dump (dump.sql)", "/dump.sql", "critical", "Exposures",
             _sql_dump, "CWE-538",
             "Remove database dumps from the web root and rotate credentials."),
    PathSpec("AEG-EXP-035", "Exposed site archive (www.zip)", "/www.zip", "high", "Exposures",
             _magic(b"PK\x03\x04", "ZIP archive"), "CWE-538",
             "Remove source archives from the web root."),
    PathSpec("AEG-EXP-036", "Exposed site archive (site.zip)", "/site.zip", "high", "Exposures",
             _magic(b"PK\x03\x04", "ZIP archive"), "CWE-538",
             "Remove source archives from the web root."),
    PathSpec("AEG-EXP-037", "Exposed site archive (wwwroot.zip)", "/wwwroot.zip", "high", "Exposures",
             _magic(b"PK\x03\x04", "ZIP archive"), "CWE-538",
             "Remove source archives from the web root."),
    PathSpec("AEG-EXP-038", "Exposed site archive (archive.zip)", "/archive.zip", "high", "Exposures",
             _magic(b"PK\x03\x04", "ZIP archive"), "CWE-538",
             "Remove source archives from the web root."),
    PathSpec("AEG-EXP-039", "Exposed PHP config backup", "/config.php.bak", "high", "Exposures",
             _all("<?php", "define(", label="PHP configuration backup"), "CWE-538",
             "Remove backup files and configure the server to deny .bak requests."),
    PathSpec("AEG-EXP-040", "Exposed PHP config copy", "/config.old", "high", "Exposures",
             _all("<?php", label="PHP configuration"), "CWE-538",
             "Remove stale configuration files from the web root."),
    PathSpec("AEG-EXP-041", "Exposed WordPress config backup", "/wp-config.php.bak", "critical", "Exposures",
             _all("DB_PASSWORD", "DB_NAME", label="WordPress database configuration"), "CWE-538",
             "Remove the backup, deny .bak files, and rotate database credentials and salts."),
    PathSpec("AEG-EXP-042", "Exposed WordPress config copy", "/wp-config.php.old", "critical", "Exposures",
             _all("DB_PASSWORD", label="WordPress database configuration"), "CWE-538",
             "Remove the stale config and rotate database credentials and salts."),
    PathSpec("AEG-EXP-043", "Exposed ASP.NET web.config", "/web.config", "medium", "Exposures",
             _all("<configuration", label="ASP.NET configuration"), "CWE-538",
             "Deny direct access to web.config and remove secrets from configuration files."),
    PathSpec("AEG-EXP-044", "Exposed Apache .htaccess", "/.htaccess", "medium", "Exposures",
             _rx(r"RewriteEngine|AuthType|Require\s|Options\s", "Apache configuration directive"), "CWE-538",
             "Deny direct access to .htaccess at the web server."),
    PathSpec("AEG-EXP-045", "Exposed composer.json", "/composer.json", "low", "Exposures",
             _all('"require"', label="Composer manifest"), "CWE-538",
             "Deny access to dependency manifests or remove them from the web root."),
    PathSpec("AEG-EXP-046", "Exposed package.json", "/package.json", "low", "Exposures",
             _all('"dependencies"', label="npm manifest"), "CWE-538",
             "Deny access to package.json or remove it from the web root."),
    PathSpec("AEG-EXP-047", "Exposed Dockerfile", "/Dockerfile", "low", "Exposures",
             _rx(r"(?m)^FROM\s+\S+", "Dockerfile FROM instruction"), "CWE-538",
             "Exclude build files from the deployment artifact."),
    PathSpec("AEG-EXP-048", "Exposed docker-compose file", "/docker-compose.yml", "low", "Exposures",
             _all("services:", label="Compose service definition"), "CWE-538",
             "Exclude compose files from the web root."),
    PathSpec("AEG-EXP-049", "Exposed JetBrains workspace metadata", "/.idea/workspace.xml", "low", "Exposures",
             _rx(r"<project\s+version|<component\s+name", "JetBrains project metadata"), "CWE-538",
             "Block IDE metadata directories from deployment."),
    PathSpec("AEG-EXP-050", "Exposed VS Code settings", "/.vscode/settings.json", "low", "Exposures",
             _config_keys(("editor.", "files.", "terminal."), "VS Code settings"), "CWE-538",
             "Block IDE metadata directories from deployment."),
    PathSpec("AEG-EXP-051", "Exposed application configuration JSON", "/config.json", "high", "Exposures",
             _config_keys(("secret", "password", "apiKey", "api_key", "token", "database", "connectionString"),
                          "Configuration keys"), "CWE-538",
             "Remove the config from the web root, deny access, and rotate exposed secrets."),
    PathSpec("AEG-EXP-052", "Exposed PHP error log", "/error.log", "medium", "Exposures",
             _rx(r"PHP (?:Fatal|Warning|Parse) error|Stack trace|Traceback", "Error log entry"), "CWE-538",
             "Write logs outside the web root and deny access to log files."),
    PathSpec("AEG-EXP-053", "Exposed application debug log", "/debug.log", "medium", "Exposures",
             _rx(r"PHP (?:Fatal|Warning|Parse) error|Stack trace|Traceback|DEBUG", "Debug log entry"), "CWE-538",
             "Write logs outside the web root and disable debug logging in production."),
    PathSpec("AEG-EXP-054", "Exposed access log", "/access.log", "medium", "Exposures",
             _rx(r"\d{1,3}(?:\.\d{1,3}){3}\s+-\s+-\s+\[", "Common access-log line"), "CWE-538",
             "Write logs outside the web root and deny access to log files."),
    PathSpec("AEG-EXP-055", "Exposed phpinfo page", "/phpinfo.php", "medium", "Exposures",
             _all("PHP Version", label="phpinfo output"), "CWE-200",
             "Remove phpinfo scripts and disable exposed PHP configuration details."),
    PathSpec("AEG-EXP-056", "Exposed PHP information page", "/info.php", "medium", "Exposures",
             _all("PHP Version", label="phpinfo output"), "CWE-200",
             "Remove phpinfo scripts from production."),
    PathSpec("AEG-EXP-057", "Exposed PHP error log (php_errorlog)", "/php_errorlog", "medium", "Exposures",
             _rx(r"PHP (?:Fatal|Warning|Parse) error", "PHP error entry"), "CWE-538",
             "Move the error log outside the web root."),
    PathSpec("AEG-EXP-058", "Exposed Apache server-status", "/server-status", "medium", "Exposures",
             _rx(r"Apache Server Status|requests currently being processed", "Apache status page"), "CWE-200",
             "Restrict server-status to localhost or disable the module."),
    PathSpec("AEG-EXP-059", "Exposed Apache server-info", "/server-info", "medium", "Exposures",
             _rx(r"Apache Server Information|Server Settings", "Apache info page"), "CWE-200",
             "Restrict server-info to localhost or disable the module."),
    PathSpec("AEG-EXP-060", "Exposed ELMAH error log", "/elmah.axd", "medium", "Exposures",
             _rx(r"Error Log for|ELMAH", "ELMAH log"), "CWE-200",
             "Disable ELMAH remote access or require authentication."),
    PathSpec("AEG-EXP-061", "Exposed ASP.NET trace", "/trace.axd", "high", "Exposures",
             _rx(r"Application Trace|Trace Information|Request Details", "ASP.NET trace"), "CWE-200",
             "Disable trace.axd in production."),
    PathSpec("AEG-EXP-062", "Exposed Adminer database client", "/adminer.php", "medium", "Exposures",
             _rx(r"Adminer", "Adminer login"), "CWE-200",
             "Remove Adminer from production or restrict it to trusted networks."),
    PathSpec("AEG-EXP-063", "Exposed Spring Actuator environment", "/actuator/env", "high", "Exposures",
             _config_keys(("propertySources", "activeProfiles", "systemProperties"), "Actuator environment data"), "CWE-200",
             "Restrict Actuator endpoints and disable env exposure."),
    PathSpec("AEG-EXP-064", "Exposed Spring Actuator health", "/actuator/health", "info", "Exposures",
             _all('"status"', label="Actuator health response"), "CWE-200",
             "Restrict Actuator endpoints to trusted networks."),
    PathSpec("AEG-EXP-065", "Exposed Spring Actuator mappings", "/actuator/mappings", "low", "Exposures",
             _config_keys(("mappings", "contexts", "dispatcherServlets"), "Actuator mappings"), "CWE-200",
             "Restrict Actuator endpoints and disable mappings exposure."),
    PathSpec("AEG-EXP-066", "Exposed Swagger UI", "/swagger-ui.html", "medium", "Exposures",
             _all("swagger", label="Swagger UI"), "CWE-200",
             "Require authentication for API documentation in production."),
    PathSpec("AEG-EXP-067", "Exposed Swagger UI (index)", "/swagger-ui/index.html", "medium", "Exposures",
             _all("swagger", label="Swagger UI"), "CWE-200",
             "Require authentication for API documentation in production."),
    PathSpec("AEG-EXP-068", "Exposed OpenAPI document", "/openapi.json", "medium", "Exposures",
             _all('"openapi"', '"paths"', label="OpenAPI document"), "CWE-200",
             "Restrict machine-readable API specifications in production."),
    PathSpec("AEG-EXP-069", "Exposed OpenAPI document (v3)", "/v3/api-docs", "medium", "Exposures",
             _all('"openapi"', label="OpenAPI document"), "CWE-200",
             "Restrict machine-readable API specifications in production."),
    PathSpec("AEG-EXP-070", "Exposed Swagger API document", "/api-docs", "medium", "Exposures",
             _all("swagger", label="Swagger document"), "CWE-200",
             "Restrict API documentation in production."),
    PathSpec("AEG-EXP-071", "Exposed H2 database console", "/h2-console", "high", "Exposures",
             _all("h2 console", label="H2 console"), "CWE-200",
             "Disable the H2 console or bind it to localhost with authentication."),
    PathSpec("AEG-EXP-072", "Exposed Jenkins script console", "/jenkins/script", "high", "Exposures",
             _all("script console", label="Jenkins script console"), "CWE-200",
             "Require authentication and remove anonymous read access from Jenkins."),
    PathSpec("AEG-EXP-073", "Exposed Jenkins dashboard", "/jenkins/", "medium", "Exposures",
             _all("jenkins", label="Jenkins dashboard"), "CWE-200",
             "Require authentication and restrict Jenkins to trusted networks."),
    PathSpec("AEG-EXP-074", "Exposed Tomcat manager", "/manager/html", "high", "Exposures",
             _rx(r"Tomcat Web Application Manager|Manager Application", "Tomcat manager"), "CWE-200",
             "Disable the manager application or restrict it to trusted networks."),
    PathSpec("AEG-EXP-075", "Exposed Go pprof endpoint", "/debug/pprof/", "medium", "Exposures",
             _all("profile", "goroutine", label="Go pprof profiles"), "CWE-200",
             "Disable net/http/pprof in production or restrict access."),
    PathSpec("AEG-EXP-076", "Exposed Prometheus metrics", "/metrics", "low", "Exposures",
             _all("# HELP", "# TYPE", label="Prometheus metrics"), "CWE-200",
             "Restrict the metrics endpoint to the monitoring network."),
    PathSpec("AEG-EXP-077", "Exposed phpMyAdmin", "/phpmyadmin/", "medium", "Exposures",
             _all("phpmyadmin", label="phpMyAdmin login"), "CWE-200",
             "Restrict phpMyAdmin to trusted networks or remove it from production."),
    PathSpec("AEG-EXP-078", "Exposed admin panel", "/admin/", "low", "Exposures",
             _admin_panel, "CWE-200",
             "Restrict administrative interfaces and enforce strong authentication."),
    PathSpec("AEG-EXP-079", "Exposed administrator panel", "/administrator/", "low", "Exposures",
             _admin_panel, "CWE-200",
             "Restrict administrative interfaces and enforce strong authentication."),
    PathSpec("AEG-EXP-080", "WordPress user enumeration API", "/wp-json/wp/v2/users", "medium", "Exposures",
             _all('"slug"', label="WordPress user objects"), "CWE-200",
             "Restrict the users endpoint or disable anonymous REST user listing."),
    PathSpec("AEG-EXP-081", "WordPress XML-RPC enabled", "/xmlrpc.php", "low", "Exposures",
             _all("xml-rpc", label="XML-RPC endpoint"), "CWE-200",
             "Disable XML-RPC if unused or protect it with rate limiting and authentication."),
    PathSpec("AEG-EXP-082", "WordPress version in readme", "/readme.html", "low", "Exposures",
             _all("wordpress", label="WordPress readme"), "CWE-200",
             "Remove readme.html and hide WordPress version details."),
    PathSpec("AEG-EXP-083", "Exposed WordPress debug log", "/wp-content/debug.log", "medium", "Exposures",
             _rx(r"PHP (?:Fatal|Warning|Notice) error|Stack trace", "WordPress debug log"), "CWE-538",
             "Disable WP_DEBUG_LOG and deny access to wp-content logs."),
    PathSpec("AEG-EXP-084", "Permissive crossdomain.xml", "/crossdomain.xml", "medium", "Exposures",
             _rx(r"allow-access-from[^>]*domain\s*=\s*[\"']\*", "Wildcard crossdomain policy"), "CWE-942",
             "Restrict Flash cross-domain policies to trusted origins or remove the file."),
    PathSpec("AEG-EXP-085", "Permissive clientaccesspolicy.xml", "/clientaccesspolicy.xml", "medium", "Exposures",
             _rx(r"allow-from[^>]*uri\s*=\s*[\"']\*|domain\s*=\s*[\"']\*", "Wildcard Silverlight policy"), "CWE-942",
             "Restrict cross-domain access policies or remove the file."),
]


def _path_runner(spec: PathSpec):
    def runner(ctx: CheckContext):
        url = ctx.target.root_url(spec.path)
        response = ctx.client.get(url, follow=True)
        if response.error or response.status not in (200, 206):
            return None
        requested = spec.path.rstrip("/") or "/"
        final = urlsplit(response.url).path.rstrip("/") or "/"
        if final != requested and not final.startswith(requested + "/"):
            return None
        if ctx.soft_404 is not None and ctx.soft_404.status == 200:
            if similarity(ctx.soft_404.text, response.text) > 0.92:
                return None
        evidence = spec.matcher(response)
        if not evidence:
            return None
        return ctx.finding(evidence, url=response.url or url, source=SOURCE_ACTIVE)

    return runner


for _spec in PATHS:
    register(
        _spec.check_id,
        _spec.title,
        _spec.category,
        _spec.severity,
        SCOPE_TARGET,
        cwe=_spec.cwe,
        remediation=_spec.remediation,
        description=_spec.description or "Sensitive file or administrative endpoint reachable without authentication.",
        source=SOURCE_ACTIVE,
    )(_path_runner(_spec))


# --------------------------------------------------------------------- TLS
def _tls(ctx: CheckContext) -> dict:
    return (ctx.shared or {}).get("tls", {}) or {}


@register(
    "AEG-TLS-001",
    "HTTPS endpoint unavailable",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-319",
    remediation="Serve the application over HTTPS with a valid certificate and redirect HTTP traffic.",
    description="Without HTTPS, credentials and session cookies travel in plaintext.",
    source=SOURCE_ACTIVE,
)
def https_unavailable(ctx: CheckContext):
    if ctx.target.scheme == "https":
        return None
    info = _tls(ctx)
    if info.get("supported"):
        return None
    return ctx.finding(f"No TLS handshake succeeded: {info.get('error', 'unknown error')}")


@register(
    "AEG-TLS-002",
    "HTTP does not redirect to HTTPS",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-319",
    remediation="Redirect all HTTP requests to HTTPS with a 301/308 and enable HSTS.",
    description="Plaintext endpoints remain reachable and can serve or accept unprotected content.",
    source=SOURCE_ACTIVE,
)
def http_no_redirect(ctx: CheckContext):
    info = _tls(ctx)
    if not info.get("supported"):
        return None
    parts = urlsplit(ctx.entry.url if ctx.entry else ctx.target.url)
    http_url = f"http://{parts.netloc}{parts.path or '/'}"
    if parts.query:
        http_url += "?" + parts.query
    response = ctx.client.get(http_url, follow=False)
    if response.error:
        return None
    if response.status in (301, 302, 303, 307, 308):
        location = response.header("location", "")
        if location.lower().startswith("https://"):
            return None
        return ctx.finding(f"HTTP redirects to a non-HTTPS location: {location or 'missing Location'}", url=http_url)
    if response.status < 400:
        return ctx.finding(f"HTTP returned {response.status} without redirecting to HTTPS.", url=http_url)
    return None


@register(
    "AEG-TLS-003",
    "Deprecated TLS protocol accepted",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-326",
    remediation="Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
    description="Legacy protocol versions have known weaknesses and are prohibited by modern standards.",
    source=SOURCE_ACTIVE,
)
def weak_tls(ctx: CheckContext):
    protocols = _tls(ctx).get("weak_protocols") or []
    if not protocols:
        return None
    return ctx.finding("Server accepted: " + ", ".join(protocols))


@register(
    "AEG-TLS-004",
    "Weak TLS cipher negotiated",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-326",
    remediation="Remove RC4, 3DES, DES, and NULL ciphers from the TLS configuration.",
    description="Obsolete ciphers reduce confidentiality or integrity guarantees.",
    source=SOURCE_ACTIVE,
)
def weak_cipher(ctx: CheckContext):
    cipher = _tls(ctx).get("weak_cipher")
    if not cipher:
        return None
    return ctx.finding(f"Negotiated weak cipher: {cipher}")


@register(
    "AEG-TLS-005",
    "TLS certificate expired or expiring soon",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-298",
    remediation="Renew certificates before expiry and monitor expiry automatically.",
    description="Expired certificates cause browser errors and encourage users to bypass warnings.",
    source=SOURCE_ACTIVE,
)
def cert_expiry(ctx: CheckContext):
    info = _tls(ctx)
    days = info.get("days_left")
    if days is None:
        return None
    if days < 0:
        return ctx.finding(f"Certificate expired {abs(days)} day(s) ago (notAfter {info.get('not_after')}).", severity="high")
    if days <= 30:
        return ctx.finding(f"Certificate expires in {days} day(s) (notAfter {info.get('not_after')}).")
    return None


@register(
    "AEG-TLS-006",
    "TLS certificate not trusted",
    "Transport",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-295",
    remediation="Use a certificate chain issued by a trusted CA.",
    description="Untrusted certificates train users to ignore warnings and permit interception.",
    source=SOURCE_ACTIVE,
)
def cert_untrusted(ctx: CheckContext):
    info = _tls(ctx)
    if not info.get("untrusted"):
        return None
    kind = "self-signed " if info.get("self_signed") else ""
    reason = (info.get("error") or "verification failed")[:220]
    return ctx.finding(f"{kind}certificate could not be verified: {reason}")


@register(
    "AEG-TLS-007",
    "TLS certificate hostname mismatch",
    "Transport",
    "high",
    SCOPE_TARGET,
    cwe="CWE-297",
    remediation="Issue a certificate whose SAN entries include the served hostname.",
    description="A hostname mismatch enables impersonation and invalidates TLS identity guarantees.",
    source=SOURCE_ACTIVE,
)
def cert_hostname(ctx: CheckContext):
    info = _tls(ctx)
    if not info.get("untrusted") or info.get("hostname_matches") is not False:
        return None
    sans = ", ".join((info.get("sans") or [])[:6]) or "none"
    return ctx.finding(f"Certificate SANs do not match {ctx.target.host}: {sans}")


# --------------------------------------------------------------- active infra
@register(
    "AEG-INF-001",
    "Directory listing enabled",
    "Exposures",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-548",
    remediation="Disable automatic directory indexes and add explicit index files.",
    description="Directory indexes disclose files that were not meant to be discoverable.",
    source=SOURCE_ACTIVE,
)
def directory_listing(ctx: CheckContext):
    hits = []
    for path in ("/backup/", "/uploads/", "/files/", "/db/", "/old/", "/private/"):
        url = ctx.target.root_url(path)
        response = ctx.client.get(url, follow=True)
        if response.error or response.status != 200:
            continue
        if _directory_listing(response):
            hits.append(url)
    if not hits:
        return None
    return ctx.finding("Indexes exposed at: " + ", ".join(hits[:5]))


@register(
    "AEG-INF-002",
    "Sensitive paths disclosed in robots.txt",
    "Exposures",
    "low",
    SCOPE_TARGET,
    cwe="CWE-200",
    remediation="Do not rely on robots.txt for secrecy; enforce authorization on sensitive paths.",
    description="robots.txt is public and often points attackers at admin, backup, or staging paths.",
    source=SOURCE_ACTIVE,
)
def robots_disclosure(ctx: CheckContext):
    url = ctx.target.root_url("/robots.txt")
    response = ctx.client.get(url, follow=True)
    if response.error or response.status != 200 or response.status == 404:
        return None
    sensitive = []
    for line in response.text.splitlines():
        match = re.match(r"(?i)^\s*disallow:\s*(\S+)", line)
        if not match:
            continue
        path = match.group(1)
        if path in ("/", "*", "") or path.startswith(("/#", "/?", "/media", "/static", "/assets", "/sitemap")):
            continue
        if re.search(r"(?i)admin|private|internal|backup|config|secret|staging|dev|test|db|log|upload|api", path):
            sensitive.append(path)
    if not sensitive:
        return None
    return ctx.finding("Sensitive Disallow entries: " + ", ".join(sorted(set(sensitive))[:8]), url=url)


@register(
    "AEG-INF-003",
    "Missing security.txt vulnerability disclosure policy",
    "Exposures",
    "info",
    SCOPE_TARGET,
    cwe="CWE-1059",
    remediation="Publish /.well-known/security.txt with a security contact and expiry.",
    description="A disclosure policy gives researchers a safe, well-known reporting channel.",
    source=SOURCE_ACTIVE,
)
def security_txt(ctx: CheckContext):
    url = ctx.target.root_url("/.well-known/security.txt")
    response = ctx.client.get(url, follow=True)
    if response.error:
        return None
    if response.status == 200 and re.search(r"(?im)^\s*contact\s*:", response.text or ""):
        return None
    return ctx.finding("No valid /.well-known/security.txt was found.", url=url)


@register(
    "AEG-INF-004",
    "GraphQL introspection enabled",
    "Exposures",
    "low",
    SCOPE_TARGET,
    cwe="CWE-200",
    remediation="Disable introspection in production or require authentication.",
    description="Introspection reveals the full schema, including private fields and mutation names.",
    source=SOURCE_ACTIVE,
)
def graphql_introspection(ctx: CheckContext):
    candidates = []
    if ctx.entry is not None:
        candidates.append(ctx.entry.url)
    candidates.append(ctx.target.root_url("/graphql"))
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        response = ctx.client.post(
            url,
            data=GRAPHQL_QUERY,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            follow=False,
        )
        if response.error or response.status != 200:
            continue
        try:
            payload = json.loads(response.text[:200000])
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict) and "__schema" in response.text and "queryType" in response.text:
            return ctx.finding("Introspection query returned a __schema/queryType response.", url=url)
        if isinstance(payload, dict) and "errors" in payload and "__schema" not in response.text:
            continue
    return None


@register(
    "AEG-INF-005",
    "Host header injection",
    "Headers",
    "medium",
    SCOPE_TARGET,
    cwe="CWE-644",
    remediation="Use a strict allowlist for Host; never reflect it into links, redirects, or password resets.",
    description="Unvalidated Host headers enable cache poisoning, reset-link poisoning, and phishing.",
    source=SOURCE_ACTIVE,
)
def host_header_injection(ctx: CheckContext):
    probe = host_probe(make_token())
    url = ctx.entry.url if ctx.entry is not None else ctx.target.url
    response = ctx.client.get(url, headers={"Host": probe}, follow=False)
    if response.error:
        return None
    reflected_in_body = probe in (response.text or "")
    location = response.header("location", "")
    reflected_in_location = probe in location
    if not (reflected_in_body or reflected_in_location):
        return None
    where = "Location header" if reflected_in_location else "response body"
    return ctx.finding(f"Attacker-controlled Host {probe!r} was reflected in the {where}.", url=url)


__all__ = ["PATHS", "PathSpec"]
