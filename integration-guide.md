# Integration Guide for NextJS Backend

## Connecting to the Trading Proxy

Update your `tradingProxy.getPortfolio` implementation in your NextJS backend to fetch data from the new endpoint:

```typescript
// lib/trading-proxy.ts

export const tradingProxy = {
  // ... other methods
  
  async getPortfolio(userId: string): Promise<any> {
    const response = await fetch(`${API_URL}/api/user/${userId}/portfolio`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`
      }
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch portfolio');
    }
    
    const data = await response.json();
    return data;
  }
};
```

The response from the proxy server will now match your portfolio model structure:

```json
{
  "userId": "6809298cda8a4ca54eb16f88",
  "totalValue": 337.95,
  "freeCapital": 50.25,
  "allocatedCapital": 287.70,
  "realizedPnl": 0,
  "unrealizedPnl": 0,
  "holdings": [
    {
      "symbol": "BTC",
      "quantity": 0.005,
      "value": 150.25,
      "price": 30050,
      "walletType": "SPOT",
      "updatedAt": "2023-05-08T13:36:22.899Z"
    },
    // ... other holdings
  ],
  "updatedAt": "2023-05-08T13:36:22.899Z"
}
```

This format matches your MongoDB schema and can be directly saved to your database.
