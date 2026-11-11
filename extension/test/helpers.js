"use strict";
// Shared test fixtures: loads the real packaged data + model weights.
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), "utf8"));

function loadData() {
  return { brands: readJson("data/brands.json"), lists: readJson("data/lists.json"), confusables: readJson("data/confusables.json") };
}

function loadModel() {
  const { UniPhishModel } = require(path.join(ROOT, "model.js"));
  const manifest = readJson("model/manifest.json");
  const raw = fs.readFileSync(path.join(ROOT, "model/weights.bin"));
  const W = new Float32Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
  return { model: new UniPhishModel().setWeights(manifest, W), manifest, W };
}

let cached = null;
function engine(withModel = true) {
  const { createEngine } = require(path.join(ROOT, "lib/engine.js"));
  if (!cached) cached = { data: loadData(), m: loadModel() };
  return createEngine({ data: cached.data, model: withModel ? cached.m.model : null });
}

module.exports = { ROOT, readJson, loadData, loadModel, engine };
