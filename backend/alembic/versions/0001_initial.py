"""Initial IPMPRS schema with pgvector support.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
from app.main import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    bind=op.get_bind()
    if bind.dialect.name == "postgresql": op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    Base.metadata.create_all(bind=bind)

def downgrade():
    # Deliberately explicit: destructive rollback is not performed automatically.
    raise RuntimeError("Refusing destructive schema downgrade; restore from backup instead.")
