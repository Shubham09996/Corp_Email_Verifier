import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import verificationRoutes from './routes/verificationRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp(): express.Application {
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Serve static UI / dashboard from public folder
  const publicPath = path.resolve(__dirname, '../../public');
  app.use(express.static(publicPath));

  // Mount API routes
  app.use(verificationRoutes);

  // Global Error Handler
  app.use(errorHandler);

  return app;
}
