"""initial schema

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("phone", sa.String(), unique=True, index=True, nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("address", sa.String(), nullable=False, server_default=""),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("car_list", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("photo_path", sa.String(), nullable=False, server_default=""),
        sa.Column("photo_mime", sa.String(), nullable=False, server_default=""),
        sa.Column("photo_updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "requests",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("user_phone", sa.String(), index=True, nullable=False),
        sa.Column("latitude", sa.Float(), nullable=False),
        sa.Column("longitude", sa.Float(), nullable=False),
        sa.Column("car_list", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("address", sa.String(), nullable=False, server_default=""),
        sa.Column("home_number", sa.String(), nullable=False, server_default=""),
        sa.Column("service_type", sa.String(), index=True, nullable=False),
        sa.Column("service_types", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("preferred_slots", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("price", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_datetime", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("finish_datetime", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), index=True, nullable=False, server_default="NEW"),
        sa.Column("driver_name", sa.String(), nullable=False, server_default=""),
        sa.Column("driver_phone", sa.String(), nullable=False, server_default=""),
        sa.Column("payment_type", sa.String(), nullable=False, server_default=""),
        sa.Column("service_place", sa.String(), nullable=False, server_default="client"),
        sa.Column("scheduled_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_start", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "reviews",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("requests.id"), unique=True, index=True, nullable=False),
        sa.Column("user_phone", sa.String(), index=True, nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("comment", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), index=True, nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.String(), nullable=True),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("token_hash", sa.String(), unique=True, index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_refresh_token_user_id_expires", "refresh_tokens", ["user_id", "expires_at"])

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("phone", sa.String(), index=True, nullable=False),
        sa.Column("ip", sa.String(), index=True, nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_login_attempt_phone_ip", "login_attempts", ["phone", "ip"])

    op.create_table(
        "schedule_slots",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("requests.id"), index=True, nullable=False),
        sa.Column("provider_phone", sa.String(), index=True, nullable=False),
        sa.Column("slot_start", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="PROPOSED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_schedule_slots_req_status", "schedule_slots", ["request_id", "status"])
    op.create_index("ix_schedule_slots_provider_slot", "schedule_slots", ["provider_phone", "slot_start"])

    op.create_table(
        "appointments",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("provider_phone", sa.String(), index=True, nullable=False),
        sa.Column("request_id", sa.Integer(), sa.ForeignKey("requests.id"), index=True, nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), index=True, nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="BOOKED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider_phone", "start_time", "end_time", name="uq_provider_slot"),
    )
    op.create_index("ix_provider_time", "appointments", ["provider_phone", "start_time", "end_time"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("user_phone", sa.String(), index=True, nullable=False),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("body", sa.String(), nullable=False, server_default=""),
        sa.Column("data", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("read", sa.Boolean(), index=True, nullable=False, server_default="false"),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index("ix_notifs_user_read_created", "notifications", ["user_phone", "read", "created_at"])

    op.create_table(
        "device_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("token", sa.String(), unique=True, index=True, nullable=False),
        sa.Column("role", sa.String(), index=True, nullable=False),
        sa.Column("platform", sa.String(), index=True, nullable=False, server_default="android"),
        sa.Column("user_phone", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tokens_role_platform", "device_tokens", ["role", "platform"])

    op.create_table(
        "promotions",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("active", sa.Boolean(), index=True, nullable=False, server_default="true"),
        sa.Column("sort_order", sa.Integer(), index=True, nullable=False, server_default="0"),
        sa.Column("title_i18n", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("subtitle_i18n", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("service_types", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("discount_amount", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("image_path", sa.String(), nullable=False, server_default=""),
        sa.Column("image_mime", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )

    op.create_table(
        "service_prices",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("service_type", sa.String(), unique=True, index=True, nullable=False),
        sa.Column("base_price", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active", sa.Boolean(), index=True, nullable=False, server_default="true"),
        sa.Column("sort_order", sa.Integer(), index=True, nullable=False, server_default="0"),
        sa.Column("name_i18n", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("icon_path", sa.String(), nullable=False, server_default=""),
        sa.Column("icon_mime", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )


def downgrade() -> None:
    for tbl in [
        "service_prices", "promotions", "device_tokens", "notifications",
        "appointments", "schedule_slots", "login_attempts",
        "refresh_tokens", "reviews", "requests", "users",
    ]:
        op.drop_table(tbl)
