"""Add administrator activation tokens.
Revision ID: 0007_activation_tokens
Revises: 0006_secure_auth
"""
from alembic import op
import sqlalchemy as sa
revision = "0007_activation_tokens"
down_revision = "0006_secure_auth"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("activation_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("station_id", sa.Integer(), sa.ForeignKey("stations.id"), nullable=False),
        sa.Column("token_hash", sa.String(128), unique=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_activation_token_active", "activation_tokens", ["token_hash", "used", "expires_at"])

def downgrade():
    op.drop_index("ix_activation_token_active", table_name="activation_tokens")
    op.drop_table("activation_tokens")
