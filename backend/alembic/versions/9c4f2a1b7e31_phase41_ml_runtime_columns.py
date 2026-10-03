"""phase 4.1: ml runtime columns on login_events

Revision ID: 9c4f2a1b7e31
Revises: 832bb849e97d
Create Date: 2026-10-03 14:30:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c4f2a1b7e31'
down_revision: Union[str, None] = '832bb849e97d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('login_events', sa.Column('ml_is_anomaly', sa.Boolean(), nullable=True))
    op.add_column('login_events', sa.Column('ml_threshold', sa.Float(), nullable=True))
    op.add_column('login_events', sa.Column('ml_model_version', sa.String(length=64), nullable=True))
    op.add_column('login_events', sa.Column('ml_details', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('login_events', 'ml_details')
    op.drop_column('login_events', 'ml_model_version')
    op.drop_column('login_events', 'ml_threshold')
    op.drop_column('login_events', 'ml_is_anomaly')
