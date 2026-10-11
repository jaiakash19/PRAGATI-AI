"""Structured decision/sanction history and curated precedent publication."""
from alembic import op
import sqlalchemy as sa

revision = "0003_structured_decisions"
down_revision = "0002_document_blob_and_ocr"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    proposal_columns = {c["name"] for c in inspector.get_columns("proposals")}
    if "precedent_visible" not in proposal_columns:
        op.add_column(
            "proposals",
            sa.Column("precedent_visible", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if "decision_records" not in inspector.get_table_names():
        op.create_table(
            "decision_records",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("proposal_id", sa.Integer(), sa.ForeignKey("proposals.id"), nullable=False),
            sa.Column("recorded_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("record_type", sa.String(length=30), nullable=False),
            sa.Column("title", sa.String(length=240), nullable=False),
            sa.Column("details", sa.Text(), nullable=False),
            sa.Column("reference_number", sa.String(length=100), nullable=True),
            sa.Column("amount", sa.Float(), nullable=True),
            sa.Column("currency", sa.String(length=3), nullable=False, server_default="INR"),
            sa.Column("effective_date", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_decision_records_proposal_id", "decision_records", ["proposal_id"])


def downgrade():
    raise RuntimeError("Refusing destructive rollback of decision and sanction history; restore from backup instead.")
