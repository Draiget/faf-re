#include "editor/doc/EdLayerPreset.h"

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  namespace
  {
    // ScmapEditor.TerrainTexture's fields in its order, the object's closing brace at `indent`.
    std::string LayerObject(const LayerSettings& layer, const std::string& indent)
    {
      const std::string in = indent + "    ";
      const float tiling[2] = {1.0f, 1.0f};
      std::string out = "{\n";
      out += in + "\"Albedo\": {\n" + in + "    \"instanceID\": 0\n" + in + "},\n";
      out += in + "\"Normal\": {\n" + in + "    \"instanceID\": 0\n" + in + "},\n";
      out += in + "\"Tilling\": " + JsonVectorText(tiling, 2, in) + ",\n";
      out += in + "\"AlbedoPath\": " + JsonQuoted(layer.albedo) + ",\n";
      out += in + "\"NormalPath\": " + JsonQuoted(layer.normals) + ",\n";
      out += in + "\"AlbedoScale\": " + JsonNumber(layer.albedoSize) + ",\n";
      out += in + "\"NormalScale\": " + JsonNumber(layer.normalsSize) + "\n";
      return out + indent + "}";
    }

    bool ReadLayer(const std::string& object, LayerSettings& layer)
    {
      std::string probe;
      if (!JsonValue(object, "AlbedoPath", probe) || !JsonValue(object, "AlbedoScale", probe)) {
        return false;
      }
      LayerSettings read;
      (void)JsonValue(object, "AlbedoPath", read.albedo);
      (void)JsonValue(object, "NormalPath", read.normals);
      (void)JsonFloat(object, "AlbedoScale", read.albedoSize);
      read.normalsSize = read.albedoSize;
      (void)JsonFloat(object, "NormalScale", read.normalsSize);
      layer = read;
      return true;
    }
  } // namespace

  std::string LayerToScmsl(const LayerSettings& layer)
  {
    return LayerObject(layer, "");
  }

  bool LayerFromScmsl(const std::string& text, LayerSettings& layer, std::string& error)
  {
    if (!ReadLayer(text, layer)) {
      error = "not a layer settings file (no AlbedoPath or AlbedoScale)";
      return false;
    }
    return true;
  }

  std::string LayersToScmst(const std::string& shader, const std::vector<LayerSettings>& layers)
  {
    std::string out = "{\n    \"ShaderName\": " + JsonQuoted(shader);
    for (std::size_t i = 0; i < 10; ++i) {
      out += ",\n    \"Stratum" + std::to_string(i) + "\": " + LayerObject(i < layers.size() ? layers[i] : LayerSettings{}, "    ");
    }
    return out + "\n}";
  }

  bool LayersFromScmst(const std::string& text, std::string& shader, std::vector<LayerSettings>& layers, std::string& error)
  {
    std::vector<LayerSettings> read(10);
    for (std::size_t i = 0; i < 10; ++i) {
      std::string object;
      if (!JsonValue(text, "Stratum" + std::to_string(i), object) || !ReadLayer(object, read[i])) {
        error = "not a layer set file (no Stratum" + std::to_string(i) + ")";
        return false;
      }
    }
    std::string name;
    (void)JsonValue(text, "ShaderName", name);
    shader = name;
    layers = std::move(read);
    return true;
  }
} // namespace faf::editor
