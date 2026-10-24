#include "hook_validation.hpp"

#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace utils::hook_validation
{
	namespace
	{
		bool is_readable(const DWORD protection) noexcept
		{
			if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
			{
				return false;
			}

			switch (protection & 0xFF)
			{
			case PAGE_READONLY:
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				return true;
			default:
				return false;
			}
		}

		bool is_executable(const DWORD protection) noexcept
		{
			switch (protection & 0xFF)
			{
			case PAGE_EXECUTE:
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				return true;
			default:
				return false;
			}
		}

		data_relocation relocation{};

		std::int32_t read_int32(const std::uint8_t* bytes) noexcept
		{
			std::int32_t value{};
			std::memcpy(&value, bytes, sizeof(value));
			return value;
		}

		bool relocated_target(const std::uintptr_t window_address, const std::int32_t displacement) noexcept
		{
			const auto in_range = [](const std::uintptr_t target)
			{
				return target >= relocation.begin && target < relocation.end;
			};

			// Image-relative disp32 (image base in a register).
			if (in_range(relocation.image_base + static_cast<std::uint32_t>(displacement)))
			{
				return true;
			}

			// RIP-relative disp32, followed by no immediate or an imm8/imm16/imm32.
			constexpr std::uintptr_t immediates[]{0, 1, 2, 4};
			for (const auto immediate : immediates)
			{
				if (in_range(window_address + 4 + immediate + static_cast<std::intptr_t>(displacement)))
				{
					return true;
				}
			}

			return false;
		}

		// Returns the end of an accepted relocated window covering index, or 0.
		// A window may run past a pattern that stops inside a displacement; its
		// unspecified high bytes then take the loaded bytes, which stay readable.
		std::size_t relocated_window_end(const std::uintptr_t start, const std::uint8_t* actual_bytes,
			const masked_byte_pattern& pattern, const std::size_t index, const std::size_t readable_end) noexcept
		{
			if (relocation.delta == 0)
			{
				return 0;
			}

			const auto first = index >= 3 ? index - 3 : 0;
			for (auto window = first; window <= index; ++window)
			{
				if (window + 4 > readable_end)
				{
					break;
				}

				auto fully_masked = true;
				std::uint8_t expected_bytes[4]{};
				for (std::size_t i = 0; i < 4; ++i)
				{
					const auto position = window + i;
					if (position < pattern.size)
					{
						fully_masked &= pattern.mask[position] == 0xFF;
						expected_bytes[i] = pattern.bytes[position];
					}
					else
					{
						expected_bytes[i] = actual_bytes[position];
					}
				}

				if (!fully_masked)
				{
					continue;
				}

				const auto expected = read_int32(expected_bytes);
				const auto actual = read_int32(actual_bytes + window);
				if (static_cast<std::int64_t>(actual) - expected == relocation.delta &&
					relocated_target(start + window, expected))
				{
					return window + 4;
				}
			}

			return 0;
		}
	}

	void set_data_relocation(const data_relocation& value) noexcept
	{
		relocation = value;
	}

	masked_byte_result verify_masked_bytes(const void* address, const masked_byte_pattern& pattern) noexcept
	{
		masked_byte_result result;
		if (!address || !pattern.bytes || !pattern.mask || pattern.size == 0)
		{
			return result;
		}

		const auto start = reinterpret_cast<std::uintptr_t>(address);
		if (pattern.size - 1 > (std::numeric_limits<std::uintptr_t>::max)() - start)
		{
			result.status = masked_byte_status::address_overflow;
			return result;
		}

		const auto* actual_bytes = static_cast<const std::uint8_t*>(address);
		std::size_t offset = 0;
		while (offset < pattern.size)
		{
			MEMORY_BASIC_INFORMATION memory{};
			if (VirtualQuery(actual_bytes + offset, &memory, sizeof(memory)) != sizeof(memory))
			{
				result.status = masked_byte_status::query_failed;
				result.checked_size = offset;
				return result;
			}

			if (memory.State != MEM_COMMIT)
			{
				result.status = masked_byte_status::uncommitted_memory;
				result.checked_size = offset;
				return result;
			}

			if (!is_readable(memory.Protect))
			{
				result.status = masked_byte_status::inaccessible_memory;
				result.checked_size = offset;
				return result;
			}

			const auto region_start = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
			if (memory.RegionSize > (std::numeric_limits<std::uintptr_t>::max)() - region_start)
			{
				result.status = masked_byte_status::address_overflow;
				result.checked_size = offset;
				return result;
			}

			const auto region_end = region_start + memory.RegionSize;
			const auto current = start + offset;
			if (current < region_start || current >= region_end)
			{
				result.status = masked_byte_status::address_overflow;
				result.checked_size = offset;
				return result;
			}

			const auto available = region_end - current;
			const auto remaining = pattern.size - offset;
			const auto chunk_size = static_cast<std::size_t>(available < remaining ? available : remaining);

			for (std::size_t i = 0; i < chunk_size; ++i)
			{
				const auto index = offset + i;
				const auto mask = pattern.mask[index];
				const auto expected = static_cast<std::uint8_t>(pattern.bytes[index] & mask);
				const auto actual = static_cast<std::uint8_t>(actual_bytes[index] & mask);
				if (actual != expected)
				{
					if (const auto window_end = relocated_window_end(start, actual_bytes, pattern, index,
						offset + static_cast<std::size_t>(available)))
					{
						i = window_end - offset - 1;
						continue;
					}

					result.status = masked_byte_status::mismatch;
					result.checked_size = index;
					result.mismatch_offset = index;
					result.expected = pattern.bytes[index];
					result.actual = actual_bytes[index];
					result.mask = mask;
					return result;
				}
			}

			offset += chunk_size;
		}

		result.status = masked_byte_status::matched;
		result.checked_size = pattern.size;
		return result;
	}

	executable_target_result validate_executable_target(const void* address) noexcept
	{
		executable_target_result result;
		result.address = address;
		if (!address)
		{
			return result;
		}

		MEMORY_BASIC_INFORMATION memory{};
		if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory))
		{
			result.status = executable_target_status::query_failed;
			return result;
		}

		result.allocation_base = memory.AllocationBase;
		result.region_base = memory.BaseAddress;
		result.region_size = memory.RegionSize;
		result.protection = memory.Protect;

		if (memory.State != MEM_COMMIT)
		{
			result.status = executable_target_status::uncommitted_memory;
		}
		else if ((memory.Protect & PAGE_GUARD) != 0)
		{
			result.status = executable_target_status::guarded_memory;
		}
		else if ((memory.Protect & PAGE_NOACCESS) != 0)
		{
			result.status = executable_target_status::no_access;
		}
		else if (!is_executable(memory.Protect))
		{
			result.status = executable_target_status::not_executable;
		}
		else
		{
			result.status = executable_target_status::executable;
		}

		return result;
	}

	const char* to_string(const masked_byte_status status) noexcept
	{
		switch (status)
		{
		case masked_byte_status::matched: return "matched";
		case masked_byte_status::invalid_argument: return "invalid argument";
		case masked_byte_status::address_overflow: return "address overflow";
		case masked_byte_status::query_failed: return "memory query failed";
		case masked_byte_status::uncommitted_memory: return "uncommitted memory";
		case masked_byte_status::inaccessible_memory: return "inaccessible memory";
		case masked_byte_status::mismatch: return "byte mismatch";
		default: return "unknown";
		}
	}

	const char* to_string(const executable_target_status status) noexcept
	{
		switch (status)
		{
		case executable_target_status::executable: return "executable";
		case executable_target_status::null_address: return "null address";
		case executable_target_status::query_failed: return "memory query failed";
		case executable_target_status::uncommitted_memory: return "uncommitted memory";
		case executable_target_status::guarded_memory: return "guarded memory";
		case executable_target_status::no_access: return "no access";
		case executable_target_status::not_executable: return "not executable";
		default: return "unknown";
		}
	}
}
