#pragma once
#include <cstdint>

namespace game::build
{
	enum class id
	{
		official,
		// 1.1.2.1279292 accessibility variant: identical code layout, but the
		// image from .data onward is mapped 0x1000 lower than the official image.
		accessibility_variant,
	};

	id get() noexcept;
	void set(id value) noexcept;
	const char* to_string(id value) noexcept;

	// Addresses in this codebase are authored against the official image.
	// Translate one to the loaded image. Code and .rdata never move.
	std::uintptr_t relocate(std::uintptr_t address) noexcept;

	template <typename T>
	T* relocate(T* address) noexcept
	{
		return reinterpret_cast<T*>(relocate(reinterpret_cast<std::uintptr_t>(address)));
	}

	// An official-image data address that resolves against the loaded image at
	// each use. Constant-initialized, so it is safe before the build is known.
	class data_address
	{
	public:
		explicit constexpr data_address(const std::uintptr_t official) noexcept
			: official_(official)
		{
		}

		operator std::uintptr_t() const noexcept
		{
			return relocate(official_);
		}

		std::uintptr_t get() const noexcept
		{
			return relocate(official_);
		}

		constexpr std::uintptr_t official() const noexcept
		{
			return official_;
		}

	private:
		std::uintptr_t official_;
	};
}
