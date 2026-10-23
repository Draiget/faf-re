#pragma once

#include <cstdint>

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "gpg/gal/Matrix.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class CubeRenderTarget;
    class RenderTarget;
    class Texture;

    /**
     * VFTABLE: 0x00D47E44
     * COL:  0x00E533C0
     *
     * One variable (effect parameter) of an Effect. Backends:
     * EffectVariableD3D9 (0x00D47E94), EffectVariableD3D10 (0x00D488DC).
     */
    class EffectVariable : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x00942F70 (FUN_00942F70)
         *
         * What it does:
         * Installs the abstract variable vtable.
         */
        EffectVariable();

        /**
         * Address: 0x00942F60 (FUN_00942F60)
         * Slot: 0
         *
         * What it does:
         * Reinstalls the abstract variable vtable; both backend destructors
         * inline it (0x0094302D, 0x0094C1B9).
         */
        virtual ~EffectVariable() = 0;

        /**
         * Slot: 1
         *
         * What it does:
         * The variable's name in the effect.
         */
        virtual msvc8::string* GetName() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Binds a cube render target's texture; a null target unbinds.
         */
        virtual void SetCubeRenderTarget(boost::shared_ptr<CubeRenderTarget> cubeTarget) = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * Binds a colour render target's texture; a null target unbinds.
         */
        virtual void SetRenderTarget(boost::shared_ptr<RenderTarget> renderTarget) = 0;

        /**
         * Slot: 4
         *
         * What it does:
         * Binds a texture; a null texture unbinds.
         */
        virtual void SetTexture(boost::shared_ptr<Texture> texture) = 0;

        /**
         * Slot: 5
         *
         * What it does:
         * Sets a 4x4 matrix.
         */
        virtual void SetMatrix4x4(const Matrix* matrix) = 0;

        /**
         * Slot: 6
         *
         * What it does:
         * Sets `count` floats.
         */
        virtual void SetFloatArray(std::uint32_t count, const float* values) = 0;

        /**
         * Slot: 7
         *
         * What it does:
         * Sets a four-float vector.
         */
        virtual void SetVector(const float* vector4) = 0;

        /**
         * Slot: 8
         *
         * What it does:
         * Sets the variable's raw bytes.
         */
        virtual void SetValue(const void* data, std::uint32_t byteCount) = 0;

        /**
         * Slot: 9
         */
        virtual void SetFloat(float value) = 0;

        /**
         * Slot: 10
         */
        virtual void SetInt(int value) = 0;

        /**
         * Slot: 11
         */
        virtual void SetBool(bool value) = 0;

        /**
         * Slot: 12
         *
         * What it does:
         * Sets `count` 4x4 matrices.
         */
        virtual void SetMatrixArray(std::uint32_t count, const Matrix* matrices) = 0;

        /**
         * Slot: 13
         *
         * What it does:
         * Sets `count` four-float vectors.
         */
        virtual void SetVectorArray(std::uint32_t count, const float* vectors4) = 0;

        /**
         * Slot: 14
         *
         * What it does:
         * Reads the variable's bool annotation `annotationName`; false when it
         * has none.
         */
        virtual bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 15
         */
        virtual bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 16
         */
        virtual bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 17
         */
        virtual bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) = 0;
    };

    static_assert(sizeof(EffectVariable) == 0x4, "gpg::gal::EffectVariable size must be 0x4");
} // namespace gpg::gal
