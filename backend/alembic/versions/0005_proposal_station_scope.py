"""Add proposal station scope.

Revision ID: 0005_proposal_station_scope
Revises: 0004_station_management
"""
from alembic import op
import sqlalchemy as sa
revision = "0005_proposal_station_scope"
down_revision = "0004_station_management"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("proposals", sa.Column("station_id", sa.Integer(), sa.ForeignKey("stations.id"), nullable=True))
    op.create_index("ix_proposals_station_id", "proposals", ["station_id"])
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE proposals SET station_id = (SELECT MIN(id) FROM stations) WHERE station_id IS NULL"))

def downgrade():
    op.drop_index("ix_proposals_station_id", table_name="proposals")
    op.drop_column("proposals", "station_id")
