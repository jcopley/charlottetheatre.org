"""empty message

Revision ID: 795e92166910
Revises: 60b6ecc67827
Create Date: 2017-11-09 16:44:22.229488

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '795e92166910'
down_revision = '60b6ecc67827'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('User', sa.Column('about_me', sa.Text(), nullable=True))
    op.add_column('User', sa.Column('last_seen', sa.DateTime(), nullable=True))
    op.add_column('User', sa.Column('location', sa.String(length=64), nullable=True))
    op.add_column('User', sa.Column('member_since', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('User', 'member_since')
    op.drop_column('User', 'location')
    op.drop_column('User', 'last_seen')
    op.drop_column('User', 'about_me')
    # ### end Alembic commands ###
