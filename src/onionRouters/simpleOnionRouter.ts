import bodyParser from "body-parser";
import express from "express";
import { base64ToArrayBuffer, rsaDecrypt, symDecrypt } from "../crypto";  // Assuming crypto functions are correctly implemented
import { BASE_ONION_ROUTER_PORT } from "../config";
import {user} from "@/src/users/user";
import {GetNodeRegistryResponse} from "@/src/registry/registry";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.get("/status/", (req, res) => {
    res.send("live")
  });

  let lastReceivedEncryptedMessage: string | null = null;

  // Implement the /getLastReceivedEncryptedMessage route
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    if (lastReceivedEncryptedMessage) {
      res.json({ result: lastReceivedEncryptedMessage });
    } else {
      res.status(404).json({ error: "No message received yet." });
    }
  });

  let lastReceivedDecryptedMessage: string | null = null;
  // Implement the /getLastReceivedDecryptedMessage route
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    if (lastReceivedDecryptedMessage) {
      res.json({ result: lastReceivedDecryptedMessage });
    } else {
      res.status(404).json({ error: "No message received yet." });
    }
  });

  let lastMessageDestination: number | null = null;
  // Implement the /getLastMessageDestination route
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    if (lastMessageDestination !== null) {
      res.json({ result: lastMessageDestination });
    } else {
      res.status(404).json({ error: "No destination found for the last received message." });
    }
  });

  // Implement the /message route
  onionRouter.post("/message", async (req:any, res:any) => {
    const { message }: { message: string } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Message is required." });
    }

    try {
      // Step 1: Decode the base64 encoded message and extract the layers
      // Decrypt the outer layer (this node's private key) from the message
      const private_key = user.nodeRegistry

      const decryptedMessage = await symDecrypt(private_key, message);
      lastReceivedEncryptedMessage = message;

      // Step 2: Extract next node or user and message
      // Assuming decryptedMessage contains [nextNodeId, encryptedSymmetricKey, encryptedMessage]
      const [nextNodeId, encryptedSymmetricKey, encryptedMessage] = decryptedMessage;

      // Step 3: Decrypt the symmetric key using RSA decryption with this node's private key
      const symmetricKey = await rsaDecrypt(encryptedSymmetricKey, user.nodeId);

      // Step 4: Decrypt the actual message using the symmetric key
      const nextMessage = await symDecrypt(encryptedMessage, symmetricKey);
      lastReceivedDecryptedMessage = nextMessage;

      // Step 5: Forward the message to the next node or user
      if (nextNodeId === "user") {
        // If destination is a user, send the message to the user
        // Assuming we have a function to send messages to the user
        const user = getUserById(nextNodeId);
        user.receiveMessage(nextMessage);  // Simulate receiving message on user side
      } else {
        // If the destination is a node, forward the message to the next node
        const nextNode = getNodeById(parseInt(nextNodeId, 10));
        nextNode.sendMessage(nextMessage);  // Simulate forwarding message to next node
      }

      // Update the destination of the message
      lastMessageDestination = parseInt(nextNodeId, 10);

      res.status(200).send("Message processed and forwarded.");
    } catch (error) {
      console.error("Error processing message:", error);
      res.status(500).json({ error: "Failed to process message." });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}

// Helper function to retrieve the next node by its ID
function getNodeById(nodeId: number) {
  // Simulate getting a node by ID from the registry
  return user.nodeRegistry.find(node => node.nodeId === nodeId);
}

// Helper function to simulate user message receiving
function getUserById(userId: string) {
  // Simulate getting the user by user ID
  return {
    receiveMessage: (message: string) => {
      console.log(`User ${userId} received message: ${message}`);
    },
  };
}
