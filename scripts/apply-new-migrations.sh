#!/bin/bash

# Apply new database migrations for visitor management, integration service, and device provisioning

set -e

echo "🚀 Applying new database migrations..."

# Get the database URL from environment
DB_URL=${DATABASE_URL:-"postgresql://localhost:5432/sparc"}

# Function to apply a migration
apply_migration() {
    local migration_file=$1
    local migration_name=$(basename "$migration_file")
    
    echo "📝 Applying migration: $migration_name"
    
    # Check if psql is available
    if command -v psql &> /dev/null; then
        psql "$DB_URL" -f "$migration_file"
    else
        echo "❌ psql command not found. Please install PostgreSQL client."
        exit 1
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully applied: $migration_name"
    else
        echo "❌ Failed to apply: $migration_name"
        exit 1
    fi
}

# Apply migrations in order
MIGRATION_DIR="packages/database/migrations"

echo "📋 Checking for new migrations..."

# Apply visitor management schema
if [ -f "$MIGRATION_DIR/0011_visitor_management_schema.sql" ]; then
    apply_migration "$MIGRATION_DIR/0011_visitor_management_schema.sql"
else
    echo "⚠️  Visitor management migration not found"
fi

# Apply integration service schema
if [ -f "$MIGRATION_DIR/0012_integration_service_schema.sql" ]; then
    apply_migration "$MIGRATION_DIR/0012_integration_service_schema.sql"
else
    echo "⚠️  Integration service migration not found"
fi

# Apply device provisioning schema
if [ -f "$MIGRATION_DIR/0013_device_provisioning_schema.sql" ]; then
    apply_migration "$MIGRATION_DIR/0013_device_provisioning_schema.sql"
else
    echo "⚠️  Device provisioning migration not found"
fi

echo ""
echo "🔧 Running Drizzle migrations..."

# Run drizzle migrations for all services
npm run db:migrate

echo ""
echo "🌱 Seeding database with sample data..."

# Run seed scripts
npm run db:seed

echo ""
echo "✅ All migrations applied successfully!"
echo ""
echo "📊 Summary:"
echo "- Visitor Management schema created"
echo "- Integration Service schema created"
echo "- Device Provisioning schema created"
echo ""
echo "🔍 Next steps:"
echo "1. Verify schema changes in your database"
echo "2. Run 'npm run db:generate' to generate TypeScript types"
echo "3. Test the new services"