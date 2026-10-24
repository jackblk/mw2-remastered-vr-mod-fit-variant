#include <std_include.hpp>
#include "game.hpp"

#include <utils/hook_validation.hpp>

namespace game
{
	namespace build
	{
		namespace
		{
			constexpr std::uintptr_t image_base = 0x140000000;
			// First official address that the accessibility variant maps lower.
			// Official .data starts here; the variant's .data starts at 0x140BE7000.
			constexpr std::uintptr_t official_data_begin = 0x140BE8000; // variant-keep
			constexpr std::uintptr_t official_image_end = 0x151E6BC00;
			constexpr std::uintptr_t variant_data_shift = 0x1000;

			id current = id::official;
		}

		id get() noexcept
		{
			return current;
		}

		void set(const id value) noexcept
		{
			current = value;
			// Expected instruction bytes are authored against the official image.
			// Accept their data displacements when they reach the same moved global.
			utils::hook_validation::set_data_relocation(value == id::accessibility_variant
				? utils::hook_validation::data_relocation{image_base, official_data_begin, official_image_end,
					-static_cast<std::intptr_t>(variant_data_shift)}
				: utils::hook_validation::data_relocation{});
		}

		const char* to_string(const id value) noexcept
		{
			switch (value)
			{
			case id::official:
				return "official";
			case id::accessibility_variant:
				return "accessibility_variant";
			default:
				return "unknown";
			}
		}

		std::uintptr_t relocate(const std::uintptr_t address) noexcept
		{
			if (current == id::accessibility_variant && address >= official_data_begin && address < official_image_end)
			{
				return address - variant_data_shift;
			}

			return address;
		}
	}

	namespace environment
	{
		launcher::mode mode = launcher::mode::none;

		launcher::mode translate_surrogate(const launcher::mode _mode)
		{
			switch (_mode)
			{
			case launcher::mode::survival:
			case launcher::mode::zombies:
				return launcher::mode::multiplayer;
			default:
				return _mode;
			}
		}

		launcher::mode get_real_mode()
		{
			if (mode == launcher::mode::none)
			{
				throw std::runtime_error("Launcher mode not valid. Something must be wrong.");
			}

			return mode;
		}

		launcher::mode get_mode()
		{
			return translate_surrogate(get_real_mode());
		}

		bool is_sp()
		{
			return get_mode() == launcher::mode::singleplayer;
		}

		bool is_mp()
		{
			return get_mode() == launcher::mode::multiplayer;
		}

		bool is_dedi()
		{
			return get_mode() == launcher::mode::server;
		}

		void set_mode(const launcher::mode _mode)
		{
			mode = _mode;
		}

		std::string get_string()
		{
			const auto current_mode = get_real_mode();
			switch (current_mode)
			{
			case launcher::mode::singleplayer:
				return "Singleplayer";

			case launcher::mode::none:
				return "None";

			default:
				return "Unknown (" + std::to_string(static_cast<int>(mode)) + ")";
			}
		}
	}
}
