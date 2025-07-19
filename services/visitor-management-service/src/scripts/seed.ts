import { db } from '../db';
// Import your schema tables here
// import { users, organizations } from '@sparc/database/schemas/visitor-management';

async function main() {
  console.log('🌱 Starting database seeding for visitor-management-service...');
  
  // TODO: Add your seed data here
  // Example:
  // await db.insert(users).values([
  //   { name: 'John Doe', email: 'john@example.com' },
  //   { name: 'Jane Smith', email: 'jane@example.com' },
  // ]);
  
  console.log('✅ Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  });
