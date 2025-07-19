import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seeding for maintenance-service...');
  
  // TODO: Add your seed data here
  // Example:
  // await prisma.model.createMany({
  //   data: [
  //     { field: 'value1' },
  //     { field: 'value2' },
  //   ],
  // });
  
  console.log('✅ Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
