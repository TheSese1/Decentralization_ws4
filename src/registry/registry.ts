import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey } from '../crypto';  // Import crypto functions

export type Node = {
  nodeId: number;
  pubKey: string
  privateKey: string;
};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
  privateKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export type GetNodeRegistryResponse = {
  nodes: {
    nodeId: number;
    pubKey: string;
  }[];
};

// Type definition for the response payload of /getPrivateKey
export type GetPrivateKeyResponse = {
  result: string; // Base64 string of the private key
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // In memory registry
  const nodeRegistry: Node[] = [];

  // TODO implement the status route
  _registry.get("/status", (req, res) => {
    res.send("live")
  });

  // HTTP POST route called /registerNode which allows for nodes
  // to register themselves on the registry
  _registry.post("/registerNode", async (req:any, res:any) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    // Validate the required fields
    if (!nodeId || !pubKey) {
      return res.status(400).json({ error: "Node ID and public key are required." });
    }

    // Check if the nodeId is already registered
    const existingNode = nodeRegistry.find((node) => node.nodeId === nodeId);
    if (existingNode) {
      return res.status(409).json({ error: "Node with this ID is already registered." });
    }

    try {
      // Generate the private key
      const {publicKey, privateKey} = await generateRsaKeyPair();

      // Export the public and private keys to base64 strings
      const publicKeyBase64 = await exportPubKey(publicKey);
      const privateKeyBase64 = await exportPrvKey(privateKey);

      // Register the node (add to in-memory registry)
      const newNode: Node = {nodeId, pubKey: publicKeyBase64, privateKey: privateKeyBase64};
      nodeRegistry.push(newNode);

      console.log(`Node ${nodeId} registered with public key ${pubKey}`);
      res.status(200).json({message: "Node registered successfully."});
    } catch (error) {
      console.error("Error during key generation:", error);
      res.status(500).json({ error: "Failed to generate key pair." });
    }
  });

  // HTTP GET route to retrieve all nodes
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    // Prepare the response payload
    const responsePayload: GetNodeRegistryResponse = {
      nodes: nodeRegistry.map((node) => ({
        nodeId: node.nodeId,
        pubKey: node.pubKey, // Send only the nodeId and public key
      })),
    };

    res.json(responsePayload);
  });

  _registry.get("/getPrivateKey", (req:any, res:any) => {
    const nodeId = parseInt(req.query.nodeId as string, 10);

    const node = nodeRegistry.find((node) => node.nodeId === nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found." });
    }

    // Base64 encode the private key and return it
    const privateKeyBase64 = Buffer.from(node.privateKey).toString('base64');

    // Respond with the base64-encoded private key
    const responsePayload: GetPrivateKeyResponse = {
      result: privateKeyBase64,
    };

    res.json(responsePayload);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
