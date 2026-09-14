"""Environment-only secrets and role-based access configuration."""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os

PERMISSIONS = {
    'viewer': {'read'}, 'ingest': {'ingest'}, 'analyst': {'read', 'ingest', 'investigate', 'recommend'},
    'approver': {'read', 'approve', 'execute'},
    'admin': {'read', 'ingest', 'investigate', 'recommend', 'approve', 'execute'},
}


@dataclass
class Settings:
    identities: list = field(default_factory=list)
    two_person: bool = False
    audit_key: str = ''
    rate_limit: int = 240

    @classmethod
    def from_env(cls):
        identities = json.loads(os.getenv('AEGIS_IDENTITIES', '[]'))
        if not isinstance(identities, list):
            raise ValueError('AEGIS_IDENTITIES must be an array')
        token = os.getenv('AEGIS_API_TOKEN', '')
        if token:
            identities.append({'name': 'local-admin', 'role': 'admin', 'token': token})
        settings = cls(identities=identities, two_person=os.getenv('AEGIS_TWO_PERSON', 'false').lower() == 'true',
                       audit_key=os.getenv('AEGIS_AUDIT_KEY', ''), rate_limit=int(os.getenv('AEGIS_RATE_LIMIT', '240')))
        settings.validate()
        return settings

    def validate(self):
        if not isinstance(self.identities, list) or not self.identities:
            raise ValueError('Configure AEGIS_API_TOKEN or AEGIS_IDENTITIES')
        names, hashes = set(), set()
        for identity in self.identities:
            if not isinstance(identity, dict) or set(identity) != {'name', 'role', 'token'}:
                raise ValueError('Each identity needs name, role, and token')
            name, token = identity['name'], identity['token']
            if not isinstance(name, str) or not name.strip() or len(name) > 100 or not isinstance(identity['role'], str) or identity['role'] not in PERMISSIONS:
                raise ValueError('Invalid identity name or role')
            if not isinstance(token, str) or len(token) < 32 or not token.isascii():
                raise ValueError('Tokens must contain at least 32 random ASCII characters')
            digest = hashlib.sha256(token.encode()).hexdigest()
            if name in names or digest in hashes:
                raise ValueError('Identity names and tokens must be unique')
            names.add(name)
            hashes.add(digest)
        if not 10 <= self.rate_limit <= 10000:
            raise ValueError('Rate limit must be 10–10000 per minute')
        if self.audit_key and len(self.audit_key) < 32:
            raise ValueError('AEGIS_AUDIT_KEY must contain at least 32 characters')

    def authenticate(self, supplied):
        candidate = hashlib.sha256(supplied.encode()).digest()
        found = None
        for identity in self.identities:
            if hmac.compare_digest(candidate, hashlib.sha256(('Bearer ' + identity['token']).encode()).digest()):
                found = {k: identity[k] for k in ('name', 'role')}
        return found

    def public(self):
        return {'ai': {'configured': False, 'provider': 'offline', 'mode': 'deterministic'},
                'response_mode': 'simulation', 'two_person_approval': self.two_person}
