/*
 * Copyright (C) 2021 Tusooa Zhu <tusooa@vista.aero>
 *
 * This file is part of libkazv.
 *
 * libkazv is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * libkazv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with libkazv.  If not, see <https://www.gnu.org/licenses/>.
 */


#pragma once
#include "libkazv-config.hpp"

#include <string>
#include <variant>
#include <immer/box.hpp>
#include <immer/flex_vector.hpp>

namespace Kazv
{
    enum struct FileOpRetCode
    {
        Error,
        Success,
        Eof
    };

    using FileContent = immer::flex_vector<char>;

    class FileStream
    {
    public:
        using DataT = FileContent;

        /**
         * Constructor.
         *
         * Construct a FileStream using `o`.
         *
         * `o` should be of a type that accepts the `read` and
         * `write` methods in this class. That is,
         * `o.read(int{}, std::function<void(FileOpRetCode, DataT)>{})`
         * and `o.write(DataT{}, std::function<void(FileOpRetCode, int)>{})`
         * must both be well-formed.
         */
        template<class DeriveT>
        FileStream(DeriveT &&o)
            : m_d(std::make_unique<Model<std::decay_t<DeriveT>>>(
                      std::forward<DeriveT>(o))) {}

        /**
         * Read at most maxSize bytes from the stream.
         *
         * This calls `readCallback(FileOpRetCode::Success, data)` upon success,
         * where `data` is a DataT containing the bytes read;
         * calls `readCallback(FileOpRetCode::Eof, DataT{})` upon meeting EOF;
         * and calls `readCallback(FileOpRetCode::Error, DataT{})` upon other errors.
         */
        template<class Callback>
        void read(int maxSize, Callback readCallback) { m_d->read(maxSize, readCallback); }

        /**
         * Write `data` into the stream.
         *
         * This calls `writeCallback(FileOpRetCode::Success, num)` upon success,
         * where `num` is an integer that contains the number of bytes written.
         * and calls `readCallback(FileOpRetCode::Error, 0)` upon other errors.
         */
        template<class Callback>
        void write(DataT data, Callback writeCallback) { m_d->write(data, writeCallback); }


    private:
        struct Concept
        {
            virtual ~Concept() = default;
            using ReadCallback = std::function<void(FileOpRetCode, DataT)>;
            using WriteCallback = std::function<void(FileOpRetCode, int)>;

            virtual void read(int maxSize, ReadCallback callback) = 0;
            virtual void write(DataT data, WriteCallback callback) = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            explicit Model(const DeriveT &o) : obj(o) {}
            explicit Model(DeriveT &&o) : obj(std::move(o)) {}
            ~Model() override = default;
            void read(int maxSize, ReadCallback callback) override {
                return obj.read(maxSize, callback);
            }
            void write(DataT data, WriteCallback callback) override {
                return obj.write(data, callback);
            }

            DeriveT obj;
        };

        std::unique_ptr<Concept> m_d;
    };

    class FileProvider
    {
    public:
        /**
         * Constructor.
         *
         * Construct a FileProvider using `o`.
         *
         * `o` should be of a copyable type `T` that has a method
         * `getStream()` that returns something implicitly convertible
         * to FileStream.
         *
         * That is, `[o]() -> FileStream { return o.getStream(); }`
         * must be well-formed.
         */
        template<class DeriveT>
        FileProvider(DeriveT &&o)
            : m_d(std::make_unique<Model<std::decay_t<DeriveT>>>(
                      std::forward<DeriveT>(o))) {}

        inline FileProvider(const FileProvider &that) : m_d(that.m_d->clone()) {}
        inline FileProvider(FileProvider &&that) : m_d(std::move(that.m_d)) {}

        inline FileProvider &operator=(const FileProvider &that) {
            m_d = that.m_d->clone();
            return *this;
        }

        inline FileProvider &operator=(FileProvider &&that) {
            m_d = std::move(that.m_d);
            return *this;
        }

        /**
         * Get the file stream provided by this.
         *
         * @return a FileStream that will contain the content
         * of the file provided by this.
         */
        inline FileStream getStream() const { return m_d->getStream(); }

    private:
        struct Concept
        {
            virtual ~Concept() = default;
            virtual std::unique_ptr<Concept> clone() const = 0;
            virtual FileStream getStream() const = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            explicit Model(const DeriveT &o) : obj(o) {}
            explicit Model(DeriveT &&o) : obj(std::move(o)) {}
            ~Model() override = default;
            std::unique_ptr<Concept> clone() const override {
                return std::make_unique<Model>(obj);
            }
            FileStream getStream() const override {
                return obj.getStream();
            }

            DeriveT obj;
        };

        std::unique_ptr<Concept> m_d;
    };

    class FileDesc;

    class FileInterface;

    struct DumbFileStream
    {
        inline explicit DumbFileStream(FileContent r) : remaining(r) {}

        template<class Callback>
        void read(int maxSize, Callback callback) {
            if (remaining.empty()) {
                callback(FileOpRetCode::Eof, remaining);
            } else {
                auto taken = remaining.take(maxSize);
                remaining = remaining.drop(maxSize);
                callback(FileOpRetCode::Success, taken);
            }
        }

        template<class Callback>
        void write(FileContent data, Callback callback) {
            remaining = remaining + data;
            callback(FileOpRetCode::Success, data.size());
        }

        FileContent remaining;
    };

    struct DumbFileProvider
    {
        inline explicit DumbFileProvider(FileContent content)
            : m_content(content)
            {}

        inline DumbFileStream getStream() const {
            return DumbFileStream(m_content);
        }

        FileContent m_content;
    };

    class FileDesc
    {
    public:
        /**
         * Construct an in-memory FileDesc with @c content.
         */
        explicit FileDesc(FileContent content)
            : m_inMemory{true}
            , m_content(content)
            {}

        /**
         * Construct a FileDesc with @c name and @c contentType.
         */
        explicit FileDesc(std::string name,
                          std::optional<std::string> contentType = std::nullopt)
            : m_inMemory{false}
            , m_name(std::move(name))
            , m_contentType(std::move(contentType)) {}

        /**
         * Get the FileProvider for this FileDesc using FileInterface.
         *
         * If this is an in-memory file, this will always return a
         * DumbFileProvider. Otherwise, it will return what
         * `fh.getProviderFor(*this)` returns.
         *
         * @return a FileProvider for this.
         */
        FileProvider provider(const FileInterface &fh) const;

        /**
         * Get the name for this FileDesc.
         */
        std::optional<std::string> name() const { return m_name; }

        /**
         * Get the content type for this FileDesc.
         */
        std::optional<std::string> contentType() const { return m_contentType; }

    private:
        const bool m_inMemory;
        FileContent m_content;
        std::optional<std::string> m_name;
        std::optional<std::string> m_contentType;
    };

    class DumbFileInterface
    {
    public:
        DumbFileProvider getProviderFor(FileDesc desc) const;
    };

    class FileInterface
    {
    public:
        template<class DeriveT>
        inline FileInterface(DeriveT &&o)
            : m_d(std::make_unique<Model<std::decay_t<DeriveT>>>(
                      std::forward<DeriveT>(o))) {}

        /**
         * Get the provider for @c desc from this.
         *
         * @warning: You should not call this directly. This
         * function is called by FileDesc::provider().
         */
        inline FileProvider getProviderFor(FileDesc desc) const {
            return m_d->getProviderFor(std::move(desc));
        }

    private:
        struct Concept
        {
            virtual ~Concept() = default;
            virtual FileProvider getProviderFor(FileDesc desc) const = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            explicit Model(const DeriveT &o) : obj(o) {}
            explicit Model(DeriveT &&o) : obj(std::move(o)) {}
            ~Model() override = default;
            FileProvider getProviderFor(FileDesc desc) const override {
                return obj.getProviderFor(std::move(desc));
            }

            DeriveT obj;
        };

        std::unique_ptr<Concept> m_d;
    };
}
