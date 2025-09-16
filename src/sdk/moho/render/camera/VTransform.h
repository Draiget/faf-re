#pragma once

#include "wm3/Plane3.h"
#include "wm3/Quaternion.h"

namespace moho
{
	class VTransform
	{
	public:
		Wm3::Quatf orient_;
		Wm3::Vec3f pos_;
	};

    /**
     * Apply a rigid transform (R,p) to a plane represented as N*X = C.
     * If geometry points are transformed as X' = R*X + p,
     * then the plane transforms to: N' = R*N, C' = C + Dot(N', p).
     */
    template <class T>
    Wm3::Plane3<T> ApplyTransform(const Wm3::Plane3<T>& pl, const VTransform& t) {
        static_assert(std::is_floating_point_v<T>, "ApplyTransform requires floating-point T");
        // We assume moho::VTransform has fields: orient (unit quaternion) and pos (Vec3f)
        // and that Wm3::Quatf::Rotate(Vec3f) is available.
        // If your types differ, adapt the rotation call accordingly.
        const auto nf = Wm3::Vec3f{
        	static_cast<float>(pl.Normal.x),
            static_cast<float>(pl.Normal.y),
            static_cast<float>(pl.Normal.z)
        };

        // rotate normal by orientation
        Wm3::Plane3<float> outF;
        const Wm3::Vec3<float> npF = t.orient_.Rotate(nf);
        outF.Normal = npF;
        outF.Constant = 
            static_cast<float>(pl.Constant) + 
            Wm3::Vec3<float>::Dot(npF, *& t.pos_);
        return Wm3::Plane3<T>::From(outF);
    }
}
