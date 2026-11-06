// Recording GAL adapter only; no production renderer implementation.
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <stdexcept>
#include <string>
#include <gtest/gtest.h>
#include <algorithm>
#include "moho/terrain/splat/CWldSplat.h"
namespace gpg {
  namespace gal {
    struct Error:std::exception {
      const char* GetFile()const {
        return "mock";
      }
      int GetLine()const {
        return 1;
      }
      const char* what()const noexcept override {
        return "injected";
      }
    };
  }
}
inline std::string expectedTechnique="TSplats";
struct Fatal {
};
inline std::vector<std::string> events;
inline int failAt=-1,step=0,passNow=-1;
inline bool nullLock=false;
inline std::vector<std::pair<int,int>> records;
inline void ev(const char*s) {
  events.emplace_back(s);
  if(step++==failAt)throw gpg::gal::Error();
}
namespace gpg {
  [[noreturn]] inline void Die(const char*,...) {
    throw Fatal {
    };
  }
  namespace gal {
    struct DrawContext {
      enum TOPOLOGY {
        TOPOLOGY_TRIANGLELIST=4
      };
    };
    struct DrawIndexedContext {
      unsigned n,inds;
      DrawIndexedContext(DrawContext::TOPOLOGY t,unsigned min,unsigned nv,unsigned ni,unsigned start,int base):n(nv),inds(ni) {
        EXPECT_TRUE(t==DrawContext::TOPOLOGY_TRIANGLELIST&&min==0&&start==0&&base==0);
        EXPECT_TRUE(n%4==0&&inds==n/4*6);
      }
    };
    struct EffectTechnique {
      int passes=1;
      int BeginTechnique() {
        ev("begin");
        return passes;
      }
      void BeginPass(int p) {
        ev("beginpass");
        passNow=p;
      }
      void EndPass() {
        ev("endpass");
        passNow=-1;
      }
      void EndTechnique() {
        ev("end");
      }
    };
    struct Device {
      static Device* GetInstance();
      void DrawIndexedPrimitive(const DrawIndexedContext*);
    };
  }
}
namespace moho {
  inline void MSDF_FlushPendingText() {
    events.emplace_back("flush");
  }
  struct ID3DVertexStream {
    std::vector<CWldSplat::SplatVertex> v;
    void* Lock(int i,int n,bool read,bool discard) {
      ev("lock");
      EXPECT_TRUE(i==0&&!read&&discard);
      v.resize(n);
      return nullLock?nullptr:v.data();
    }
    void Unlock() {
      ev("unlock");
    }
  };
  struct CD3DVertexSheet {
    ID3DVertexStream stream;
    void Func9() {
      ev("vertexbind");
    }
    ID3DVertexStream* GetVertStream(unsigned) {
      return &stream;
    }
  };
  struct CD3DIndexSheet {
    void SetBufferIndices() {
      ev("indexbind");
    }
  };
  struct Holder {
    gpg::gal::EffectTechnique* p;
    gpg::gal::EffectTechnique* get() {
      return p;
    }
  };
  struct CD3DEffect {
    Holder mCurrentTechnique;
    void SetTechnique(const char*name) {
      ev("select");
      EXPECT_TRUE(std::string(name)==expectedTechnique);
    }
  };
  struct SD3DVertexRange;
  struct SD3DIndexRange;
  struct CD3DDevice {
    CD3DEffect e;
    CD3DEffect* GetCurEffect() {
      return &e;
    }
    bool SelectTechnique(const char*);
    bool DrawTriangleList(const SD3DVertexRange*,const SD3DIndexRange*,int*);
  };
}
inline std::size_t activeCap=2500;
inline moho::CD3DVertexSheet* curSheet;
inline gpg::gal::Device gd;
inline gpg::gal::Device* gpg::gal::Device::GetInstance() {
  return &gd;
}
inline void gpg::gal::Device::DrawIndexedPrimitive(const gpg::gal::DrawIndexedContext*c) {
  ev("draw");
  EXPECT_TRUE(curSheet->stream.v.size()==c->n);
  EXPECT_TRUE(c->n<=activeCap*4);
  for(auto &v:curSheet->stream.v) {
    EXPECT_TRUE(v.mPosition.y==1.25f&&v.mPosition.z==-2.f&&v.mTexCoord.x==.2f&&v.mTexCoord.y==.7f&&v.mAlpha==.33f);
    for(auto byte:v.mPad18_1B)EXPECT_TRUE(byte==0x5a);
    records.push_back( {
      passNow,int(v.mPosition.x)
    });
  }
}
namespace boost {
  template<class T>int static_pointer_cast(int p) {
    return p;
  }
}
namespace moho {
  struct CD3DDynamicTextureSheet {
  };
  struct CD3DTextureBatcher {
    int GetCompositeTexture() {
      return 1;
    }
  };
  struct TextureVar {
    void GetTexture(int) {
      ev("atlas");
    }
  };
  struct ShaderVars {
    TextureVar decalAlbedoTexture;
  };
  inline ShaderVars shaderVars;
  inline ShaderVars& GetTerrainShaderVars() {
    return shaderVars;
  }
  inline CD3DDevice* activeDevice;
  inline CD3DDevice* D3D_GetDevice() {
    return activeDevice;
  }
  struct SD3DVertexRange {
    CD3DVertexSheet*sheet=nullptr;
    int startVertex=0,baseVertex=0,endVertex=0;
  };
  struct SD3DIndexRange {
    CD3DIndexSheet*sheet=nullptr;
    int startIndex=0,indexCount=0;
  };
  @DEVICE_METHODS@
  inline CD3DTextureBatcher atlas;
  inline CD3DTextureBatcher*sHighFidelityTextureBatcher=&atlas,*sMediumFidelityTextureBatcher=&atlas,*texture_batcher=&atlas;
  inline constexpr int kTriangleListPrimitiveToken=4,kTriangleListPrimitiveType=4;
}
