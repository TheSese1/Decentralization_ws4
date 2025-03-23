import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";
import {
  createRandomSymmetricKey,
  exportSymKey,
  rsaEncrypt,
  symEncrypt,
  base64ToArrayBuffer,
  exportPubKey,
} from "../crypto";
import {webcrypto} from "crypto";

export type Node = {
  nodeId: number;
  pubKey: string
  privateKey: string;
};

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
  privateKey: string;
};

// Function to select 3 random distinct nodes from the node registry
function selectRandomNodes(nodeRegistry: Node[]): Node[] {
  const shuffled = [...nodeRegistry].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, 3); // Select the first 3 nodes after shuffling
}

async function sendToNode(destination: string, encryptedMessage: ArrayBuffer) {
  const response = await fetch(`http://localhost:${destination}/message`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ message: encryptedMessage }),
  });

  return response;
}

export async function user(userId: number, nodeRegistry: Node[]) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  _user.get("/status/", (req, res) => {
    res.send("live")
  });


  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // Implement the /getLastReceivedMessage route
  _user.get("/getLastReceivedMessage", (req, res) => {
    if (lastReceivedMessage !== null) {
      res.json({ result: lastReceivedMessage });
    } else {
      res.status(404).json({ error: "No message received yet." });
    }
  });

  // Implement the /message route to receive messages
  _user.post("/message", (req: any, res: any) => {
    const { message }: { message: string } = req.body;

    // Validate the message
    if (!message || message.trim() === "") {
      return res.status(400).json({ error: "Message cannot be empty." });
    }

    // Update the last received message
    lastReceivedMessage = message;

    // Respond with success
    res.status(200).json({ message: "Message received successfully." });
  });

  // Implement the /getLastSentMessage route
  _user.get("/getLastSentMessage", (req, res) => {
    if (lastSentMessage !== null) {
      res.json({ result: lastSentMessage });
    } else {
      res.status(404).json({ error: "No message received yet." });
    }
  });

  _user.post("/sendMessage", async (req: any, res: any) => {
    const { message, destinationUserId }: SendMessageBody = req.body;

    if (!message || !destinationUserId) {
      return res.status(400).json({ error: "Message and destinationUserId are required." });
    }

    // create a random circuit of 3 distinct nodes from the node registry
    const randomNodes = selectRandomNodes(nodeRegistry);

    // Step 2: Encrypt the message and forward to each node
    let encryptedMessage = message;
    let symmetricKeys: webcrypto.CryptoKey[] = [];

    for (let i = 0; i < 3; i++) {
      const node = randomNodes[i];
      const symmetricKey = await createRandomSymmetricKey();

      // Store the symmetric key for later use
      symmetricKeys.push(symmetricKey);

      // Step 2.1: Encrypt the concatenated data (message + previous encrypted message) with the symmetric key
      const encryptedMessageLayer = await symEncrypt(symmetricKey, encryptedMessage);

      // Step 2.2: Encrypt the symmetric key with the node's public RSA key
      const encryptedSymmetricKey = await rsaEncrypt(
          await exportSymKey(symmetricKey),
          node.pubKey
      );

      // Step 2.3: Concatenate encrypted symmetric key and encrypted message
      encryptedMessage = encryptedSymmetricKey + encryptedMessageLayer;

      // Prepare the destination node information (nodeId + base port)
      const destination = String(node.nodeId).padStart(10, '0');

      // Forward the message to the entry node
      if (i === 0) {
        const response = await sendToNode(destination, base64ToArrayBuffer(encryptedMessage));
        if (response.status !== 200) {
          return res.status(500).json({ error: "Failed to send message to the entry node." });
        }
      }
    }

    // Respond that the message was successfully forwarded
    res.status(200).json({ message: "Message sent through onion routing." });
  });


  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
