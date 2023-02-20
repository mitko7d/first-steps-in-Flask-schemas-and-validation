"""many to many

Revision ID: aca328f4882d
Revises: a3caeab172e9
Create Date: 2023-02-21 00:47:38.318105

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aca328f4882d'
down_revision = 'a3caeab172e9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users_clothes',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('clothes_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['clothes_id'], ['clothes.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users_clothes')
    # ### end Alembic commands ###