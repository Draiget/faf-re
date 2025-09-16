#pragma once
#include <corecrt_math.h>

#include "Vector4f.h"

namespace moho
{
	struct Vector3f
	{
		float x;
		float y;
		float z;

		static Vector3f left;
		static Vector3f right;
		static Vector3f top;
		static Vector3f bottom;
		static Vector3f up;
		static Vector3f down;

		Vector3f(const float x, const float y, const float z) {
			this->x = x;
			this->y = y;
			this->z = z;
		}

		Vector3f(const Vector3f& b) {
			this->x = b.x;
			this->y = b.y;
			this->z = b.z;
		}

		explicit Vector3f(const float value) {
			this->x = value;
			this->y = value;
			this->z = value;
		}

		Vector3f() : Vector3f(0) {}

		Vector3f operator-(const Vector3f& dst) const {
			return { this->x - dst.x, this->y - dst.y, this->z - dst.z };
		}

		Vector3f operator/(const float number) const {
			return { this->x / number, this->y / number, this->z / number };
		}

		Vector3f operator*(const float number) const {
			return { this->x * number, this->y * number, this->z * number };
		}

		Vector3f operator+(const Vector3f& dst) const {
			return { this->x + dst.x, this->y + dst.y, this->z + dst.z };
		}

		[[nodiscard]] Vector3f rotate(const Vector3f& axis, const float theta) const {
			return rotate(*this, axis, theta);
		}

		[[nodiscard]] Vector3f rotate(const Vector4f& q) const;

		[[nodiscard]] float magnitude() const;

		[[nodiscard]] float dot(const Vector3f dst) const {
			return this->x * dst.x + this->y * dst.y + this->z * dst.z;
		}

		[[nodiscard]] Vector3f cross(const Vector3f& rhs) const {
			return {
				y * rhs.z - z * rhs.y,
				z * rhs.x - x * rhs.z,
				x * rhs.y - y * rhs.x
			};
		}

		[[nodiscard]] float distance_approx(Vector3f b) const;
		[[nodiscard]] float distance(Vector3f b) const;

		[[nodiscard]] Vector3f lerp(const Vector3f b, const float t) const {
			return Vector3f(*this * t + b * (1.f - t));
		}

		static Vector3f rotate(const Vector3f& v, const Vector3f& axis, const float theta) {
			const auto cos_theta = cosf(theta);
			const auto sin_theta = sinf(theta);

			return (v * cos_theta) + (axis.cross(v) * sin_theta) + (axis * axis.dot(v)) * (1 - cos_theta);
		}

		static Vector3f rotate(const Vector3f& v, const Vector4f& q);
	};
}
