import { createApp } from './app.js';
import { config } from './config/index.js';

const app = createApp();

const server = app.listen(config.port, config.host, () => {
  console.log(`====================================================`);
  console.log(`🚀 Email Verification API Server Running!`);
  console.log(`📡 URL: http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`);
  console.log(`🛠️  Health Check: http://localhost:${config.port}/api/health`);
  console.log(`🔍 Verification Endpoint: POST http://localhost:${config.port}/api/verify`);
  console.log(`🏢 Corporate Alias: POST http://localhost:${config.port}/api/verify-corporate-email`);
  console.log(`🌐 Domain Age Endpoint: POST http://localhost:${config.port}/api/domain-age`);
  console.log(`⚡ Mode: ${config.nodeEnv}`);
  console.log(`====================================================`);
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});
