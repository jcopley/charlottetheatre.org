"""empty message

Revision ID: 60b6ecc67827
Revises: b65bc9380e42
Create Date: 2017-11-09 10:41:27.165902

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '60b6ecc67827'
down_revision = 'b65bc9380e42'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('Role', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('Role', sa.Column('permissions', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_Role_default'), 'Role', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_Role_default'), table_name='Role')
    op.drop_column('Role', 'permissions')
    op.drop_column('Role', 'default')
    # ### end Alembic commands ###