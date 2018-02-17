"""empty message

Revision ID: cec211813953
Revises: 56b64e6ec8a6
Create Date: 2017-11-03 18:13:55.619383

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cec211813953'
down_revision = '56b64e6ec8a6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    # ### end Alembic commands ###
    pass


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_index('ix_User_username', 'User', ['username'], unique=1)
    op.create_index('ix_User_email', 'User', ['email'], unique=1)
    op.drop_index(op.f('ix_User_username'), table_name='User')
    op.drop_index(op.f('ix_User_name'), table_name='User')
    op.drop_index(op.f('ix_User_email'), table_name='User')
    op.drop_column('User', 'name')
    # ### end Alembic commands ###