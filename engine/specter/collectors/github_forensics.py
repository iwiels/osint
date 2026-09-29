"""
WraithOSINT - GitHub Deep Forensic Investigator
Extracción forense avanzada de perfiles de GitHub: repositorios, commits, emails de autores,
claves públicas SSH/GPG y enlaces a redes/Discord en descripciones de repositorios.
"""

import json
import re
from typing import Any

import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)


class GitHubForensics(BaseCollector):
    def __init__(self):
        super().__init__(name="github_forensics")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip().lstrip("@")
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        forensic_report: dict[str, Any] = {"username": username}

        # Nodo de identidad
        alias_node = EntityNode.create(EntityType.ALIAS, username, f"Alias: @{username}")
        entities.append(alias_node)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            # 1. Perfil Base
            user_resp = await client.get(f"https://api.github.com/users/{username}")
            if user_resp.status_code != 200:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=username,
                    entities=entities,
                    relations=relations,
                    raw_payload=json.dumps(
                        {"error": "User not found on GitHub", "status": user_resp.status_code}
                    ),
                )

            user_data = user_resp.json()
            forensic_report["profile"] = user_data

            prof_node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE,
                value=user_data.get("html_url", f"https://github.com/{username}"),
                label=f"GitHub: @{username}",
                attributes={
                    "name": user_data.get("name"),
                    "bio": user_data.get("bio"),
                    "company": user_data.get("company"),
                    "location": user_data.get("location"),
                    "created_at": user_data.get("created_at"),
                    "public_repos": user_data.get("public_repos"),
                    "blog": user_data.get("blog"),
                },
                confidence=1.0,
            )
            entities.append(prof_node)
            relations.append(
                RelationEdge(
                    source_id=alias_node.id,
                    target_id=prof_node.id,
                    relation_type=RelationType.REGISTERED_WITH,
                    confidence=1.0,
                )
            )

            # Nombre real si está disponible
            if user_data.get("name"):
                real_name = user_data["name"].strip()
                person_node = EntityNode.create(
                    EntityType.PERSON, real_name, f"Person: {real_name}"
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=alias_node.id,
                        relation_type=RelationType.USES_ALIAS,
                    )
                )

            # 2. Claves SSH públicas
            keys_resp = await client.get(f"https://github.com/{username}.keys")
            if keys_resp.status_code == 200 and keys_resp.text.strip():
                ssh_keys = [k.strip() for k in keys_resp.text.strip().split("\n") if k.strip()]
                forensic_report["ssh_keys"] = ssh_keys
                for k in ssh_keys:
                    key_node = EntityNode.create(
                        type=EntityType.FILE_ARTIFACT,
                        value=k[:50] + "...",
                        label=f"SSH Key ({k.split()[0]})",
                        attributes={"full_key": k, "type": "SSH Public Key"},
                    )
                    entities.append(key_node)
                    relations.append(
                        RelationEdge(
                            source_id=prof_node.id,
                            target_id=key_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )

            # 3. Repositorios y minería de emails en commits
            repos_resp = await client.get(
                f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10"
            )
            discovered_emails = set()
            external_links = set()

            if repos_resp.status_code == 200:
                repos = repos_resp.json()
                forensic_report["repositories"] = [r.get("name") for r in repos]

                for repo in repos:
                    repo_name = repo.get("name")
                    repo_desc = repo.get("description") or ""

                    # Extraer enlaces a Discord o sitios externos en la descripción
                    discord_matches = re.findall(
                        r"https?://discord(?:\.gg|app\.com/invite)/[a-zA-Z0-9]+", repo_desc
                    )
                    for d_link in discord_matches:
                        external_links.add(d_link)

                    # Minar commits del repositorio en busca de emails reales
                    try:
                        commits_resp = await client.get(
                            f"https://api.github.com/repos/{username}/{repo_name}/commits?per_page=5"
                        )
                        if commits_resp.status_code == 200:
                            for c in commits_resp.json():
                                author = c.get("commit", {}).get("author", {})
                                c_email = author.get("email")
                                c_name = author.get("name")
                                if c_email and "noreply" not in c_email:
                                    discovered_emails.add((c_email, c_name))
                    except Exception:
                        pass

            forensic_report["discovered_commit_emails"] = list(discovered_emails)
            forensic_report["external_links"] = list(external_links)

            # Agregar emails descubiertos en commits al grafo
            for email_val, email_name in discovered_emails:
                email_node = EntityNode.create(
                    type=EntityType.EMAIL,
                    value=email_val,
                    label=f"Email: {email_val}",
                    attributes={"author_name": email_name, "source": "GitHub Commit Log"},
                    confidence=0.98,
                )
                entities.append(email_node)
                relations.append(
                    RelationEdge(
                        source_id=alias_node.id,
                        target_id=email_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                        confidence=0.98,
                    )
                )

            # Agregar enlaces externos (Discord, etc.)
            for ext in external_links:
                ext_node = EntityNode.create(
                    type=EntityType.SOCIAL_PROFILE,
                    value=ext,
                    label=f"External: {ext}",
                    attributes={"source": "Repository Description"},
                )
                entities.append(ext_node)
                relations.append(
                    RelationEdge(
                        source_id=prof_node.id,
                        target_id=ext_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=username,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(forensic_report, indent=2, default=str),
            metadata={
                "repos_analyzed": len(forensic_report.get("repositories", [])),
                "emails_extracted": len(discovered_emails),
                "external_links_found": len(external_links),
            },
        )
