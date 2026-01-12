import { defineConfig } from '@prisma/config';

export default defineConfig({
  datasource: {
    // Prisma 7 lira DATABASE_URL depuis ton .env via ce fichier
    url: process.env.DATABASE_URL,
  },
});