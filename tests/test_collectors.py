from pathlib import Path

import pytest
from PIL import Image
from pypdf import PdfWriter
from specter.collectors.artifacts import FileForensics
from specter.collectors.identity import EmailInvestigator
from specter.osint_core.models import EntityType, RelationType


@pytest.mark.asyncio
async def test_file_forensics_image(tmp_path: Path):
    img_path = tmp_path / "forensic_sample.jpg"
    img = Image.new("RGB", (100, 100), color="blue")
    img.save(img_path)

    collector = FileForensics()
    result = await collector.collect(str(img_path))

    assert result.collector_name == "file_forensics"
    assert len(result.entities) >= 1

    file_node = result.entities[0]
    assert file_node.type == EntityType.FILE_ARTIFACT
    assert "hashes" in file_node.attributes
    assert len(file_node.attributes["hashes"]["sha256"]) == 64
    assert len(file_node.attributes["hashes"]["md5"]) == 32


@pytest.mark.asyncio
async def test_file_forensics_pdf(tmp_path: Path):
    pdf_path = tmp_path / "case_doc.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_metadata(
        {
            "/Author": "Investigador Forense X",
            "/Producer": "OSINT-Toolsuite",
        }
    )
    with open(pdf_path, "wb") as f:
        writer.write(f)

    collector = FileForensics()
    result = await collector.collect(str(pdf_path))

    author_nodes = [e for e in result.entities if e.type == EntityType.PERSON]
    assert len(author_nodes) == 1
    assert author_nodes[0].value == "Investigador Forense X"

    meta_relations = [
        r for r in result.relations if r.relation_type == RelationType.CONTAINS_METADATA
    ]
    assert len(meta_relations) == 1


@pytest.mark.asyncio
async def test_email_investigator():
    collector = EmailInvestigator()
    result = await collector.collect("analista.cero@ejemplo.test")

    assert result.collector_name == "email_investigator"
    email_nodes = [e for e in result.entities if e.type == EntityType.EMAIL]
    assert len(email_nodes) == 1
    assert email_nodes[0].value == "analista.cero@ejemplo.test"

    alias_nodes = [e for e in result.entities if e.type == EntityType.ALIAS]
    assert len(alias_nodes) == 1
    assert alias_nodes[0].value == "analista.cero"

    domain_nodes = [e for e in result.entities if e.type == EntityType.DOMAIN]
    assert len(domain_nodes) == 1
    assert domain_nodes[0].value == "proton.me"
