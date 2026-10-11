"""Add stations, memberships, ranks and cross-station requests.

Revision ID: 0004_station_management
Revises: 0003_structured_decisions
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_station_management"
down_revision = "0003_structured_decisions"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("rank", sa.String(length=30), nullable=True))
    op.create_table(
        "stations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(length=40), nullable=False, unique=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("region", sa.String(length=40), nullable=False),
        sa.Column("station_type", sa.String(length=40), nullable=False, server_default="Police Station"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_table(
        "station_memberships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("station_id", sa.Integer(), sa.ForeignKey("stations.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assignment_role", sa.String(length=30), nullable=False, server_default="Member"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("assigned_at", sa.DateTime(), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_station_memberships_station_active", "station_memberships", ["station_id", "active"])
    op.create_index("uq_station_memberships_active_user", "station_memberships", ["station_id", "user_id"], unique=True, postgresql_where=sa.text("active = true"), sqlite_where=sa.text("active = 1"))
    op.create_table(
        "cross_station_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("request_reference", sa.String(length=50), nullable=False, unique=True),
        sa.Column("source_station_id", sa.Integer(), sa.ForeignKey("stations.id"), nullable=False),
        sa.Column("destination_station_id", sa.Integer(), sa.ForeignKey("stations.id"), nullable=False),
        sa.Column("requested_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("responded_by_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("shared_information", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="Pending"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("responded_at", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("cross_station_requests")
    op.drop_index("uq_station_memberships_active_user", table_name="station_memberships")
    op.drop_index("ix_station_memberships_station_active", table_name="station_memberships")
    op.drop_table("station_memberships")
    op.drop_table("stations")
    op.drop_column("users", "rank")
