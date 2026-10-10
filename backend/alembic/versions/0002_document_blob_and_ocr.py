"""Persist original case files in DB and record digitization/OCR metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0002_document_blob_and_ocr"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    # The initial migration uses Base.metadata.create_all(); fresh databases
    # may already have these model columns. Handle both old and fresh installs.
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("documents")}
    if "content_blob" not in existing:
        op.add_column("documents", sa.Column("content_blob", sa.LargeBinary(), nullable=True))
    if "document_type" not in existing:
        op.add_column("documents", sa.Column("document_type", sa.String(length=50), nullable=False, server_default="Supporting Document"))
    if "ocr_status" not in existing:
        op.add_column("documents", sa.Column("ocr_status", sa.String(length=40), nullable=False, server_default="not_required"))


def downgrade():
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("documents")}
    if "ocr_status" in existing:
        op.drop_column("documents", "ocr_status")
    if "document_type" in existing:
        op.drop_column("documents", "document_type")
    if "content_blob" in existing:
        op.drop_column("documents", "content_blob")
