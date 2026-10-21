// securemem.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2026 Ake Hedman, the VSCP project
// <info@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

/*!
    @brief Helpers for keeping secrets out of ordinary heap memory.

    secure_string stores its characters in memory obtained from
    sodium_malloc(). That memory is locked (not swapped to disk where the
    platform allows it), surrounded by guard pages, excluded from core dumps
    on Linux and wiped by sodium_free() when released.
*/

#if !defined(VSCP_SECUREMEM_H__INCLUDED_)
#define VSCP_SECUREMEM_H__INCLUDED_

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <vector>

template<typename T>
struct SodiumAllocator {
    using value_type = T;

    SodiumAllocator() noexcept = default;
    template<typename U>
    SodiumAllocator(const SodiumAllocator<U>&) noexcept
    {
    }

    T* allocate(std::size_t n)
    {
        // sodium_init() is idempotent and sets up the page size used by
        // sodium_malloc(), so it is safe to call before every allocation.
        if (sodium_init() < 0) {
            throw std::bad_alloc();
        }
        if (n > static_cast<std::size_t>(-1) / sizeof(T)) {
            throw std::bad_alloc();
        }
        void* p = sodium_malloc(n * sizeof(T));
        if (nullptr == p) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(p);
    }

    void deallocate(T* p, std::size_t) noexcept { sodium_free(p); }
};

template<typename T, typename U>
bool
operator==(const SodiumAllocator<T>&, const SodiumAllocator<U>&) noexcept
{
    return true;
}

template<typename T, typename U>
bool
operator!=(const SodiumAllocator<T>&, const SodiumAllocator<U>&) noexcept
{
    return false;
}

/*!
    String whose storage lives in locked, guarded memory that is wiped on
    release. Reserve more than the small-string buffer (16 bytes) before
    storing short secrets so they are not kept inline in the owning object.
*/
using secure_string =
  std::basic_string<char, std::char_traits<char>, SodiumAllocator<char>>;

/*!
    Minimum capacity to reserve for secure_string objects so that their
    content is always placed in sodium_malloc() memory.
*/
constexpr std::size_t SECURE_STRING_MIN_CAPACITY = 64;

/*!
    Wipe the entire buffer of a string, including spare capacity, and leave it
    empty. The buffer is kept so later assignments reuse the same memory.
*/
template<typename Traits, typename Alloc>
inline void
secure_wipe(std::basic_string<char, Traits, Alloc>& s) noexcept
{
    s.resize(s.capacity());
    sodium_memzero(&s[0], s.size());
    s.clear();
}

/*!
    Wipe the entire buffer of a byte vector, including spare capacity, and
    leave it empty.
*/
inline void
secure_wipe(std::vector<uint8_t>& v) noexcept
{
    v.resize(v.capacity());
    if (!v.empty()) {
        sodium_memzero(v.data(), v.size());
    }
    v.clear();
}

/*!
    Wipe a string when the enclosing scope exits, whichever way it exits.
*/
template<typename S>
class SecureWipeGuard {
  public:
    explicit SecureWipeGuard(S& s) noexcept
      : m_s(s)
    {
    }
    ~SecureWipeGuard() { secure_wipe(m_s); }
    SecureWipeGuard(const SecureWipeGuard&)            = delete;
    SecureWipeGuard& operator=(const SecureWipeGuard&) = delete;

  private:
    S& m_s;
};

#endif
