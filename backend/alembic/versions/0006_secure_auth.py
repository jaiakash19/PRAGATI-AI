"""Add OTP and account verification fields.
Revision ID: 0006_secure_auth
Revises: 0005_proposal_station_scope
"""
from alembic import op
import sqlalchemy as sa
revision = "0006_secure_auth"
down_revision = "0005_proposal_station_scope"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("activation_required", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table("otp_challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consumed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_otp_user_active", "otp_challenges", ["user_id", "consumed", "expires_at"])

def downgrade():
    op.drop_index("ix_otp_user_active", table_name="otp_challenges")
    op.drop_table("otp_challenges")
    op.drop_column("users", "activation_required")
    op.drop_column("users", "email_verified")
