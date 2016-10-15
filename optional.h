#ifndef OPTIONAL_H
#define OPTIONAL_H

#include <assert.h>
#include <utility>

namespace detail {

struct Empty {};
typedef void (Empty::*AbsentType)();

}

template <class T=void>
class Optional {
public:
    Optional()
        : present(false)
    {
    }

    Optional(detail::AbsentType)
        : present(false)
    {
    }

    Optional(const T& t)
        : present(true)
    {
        new (&u.t) T(t);
    }

    Optional(T&& t)
        : present(true)
    {
        new (&u.t) T(std::move(t));
    }

    ~Optional() {
        reset();
    }

    Optional(const Optional& other)
        : present(other.present)
    {
        if (present) {
            new (&u.t) T(other.u.t);
        }
    }

    Optional(Optional&& other)
        : present(other.present)
    {
        if (present) {
            new (&u.t) T(std::move(other.u.t));
            other.reset();
        }
    }

    Optional& operator =(const Optional& other) {
        present = other.present;
        if (present) {
            new (&u.t) T(other.u.t);
        }
    }

    Optional& operator =(Optional&& other) {
        present = other.present;
        if (present) {
            new (&u.t) T(std::move(other.u.t));
            other.reset();
        }
        return *this;
    }

    void reset() {
        if (present) {
            u.t.~T();
            present = false;
        }
    }

    bool isPresent() const {
        return present;
    }

    bool isAbsent() const {
        return !present;
    }

    T get() const & {
        assert(present);
        return u.t;
    }

    T get() && {
        assert(present);
        T t = std::move(u.t);
        reset();
        return t;
    }

    explicit operator bool() const {
        return present;
    }

    T& operator *() {
        assert(present);
        return u.t;
    }

    T* operator ->() {
        assert(present);
        return &u.t;
    }

private:
    union U {
        T t;
        U() {}
        ~U() {}
    } u;
    bool present;
};

template<>
class Optional<void> {
public:
    static constexpr detail::AbsentType absent = nullptr;

    template <class T, class Opt = Optional<typename std::decay<T>::type>>
    static Opt from(T&& t) {
        return Opt(std::forward<T>(t));
    }
};

#endif // OPTIONAL_H

