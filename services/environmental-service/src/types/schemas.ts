import { z } from 'zod';

// Define Zod schemas for request/response validation
export const ExampleSchema = z.object({
  id: z.string().uuid(),
  // Add fields
});

export type Example = z.infer<typeof ExampleSchema>;
