-- orders: your application table; adapt fields as needed
CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  external_order_id VARCHAR(128) NOT NULL UNIQUE,
  total_amount DECIMAL(10,2) NOT NULL,
  currency VARCHAR(8) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  transaction_id VARCHAR(128),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- webhook_logs: audit log of incoming webhooks (idempotency)
CREATE TABLE IF NOT EXISTS webhook_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  transaction_id VARCHAR(128) NOT NULL,
  order_id VARCHAR(128) NULL,
  payload JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY (transaction_id)
);
