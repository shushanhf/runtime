﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;

namespace System.Text.Json
{
    public static partial class JsonSerializer
    {
        /// <summary>
        /// Reads the UTF-8 encoded text representing a single JSON value into a <typeparamref name="TValue"/>.
        /// The PipeReader will be read to completion.
        /// </summary>
        /// <typeparam name="TValue">The type to deserialize the JSON value into.</typeparam>
        /// <returns>A <typeparamref name="TValue"/> representation of the JSON value.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="options">Options to control the behavior during reading.</param>
        /// <param name="cancellationToken">
        /// The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="JsonException">
        /// The JSON is invalid,
        /// <typeparamref name="TValue"/> is not compatible with the JSON,
        /// or when there is remaining data in the PipeReader.
        /// </exception>
        /// <exception cref="NotSupportedException">
        /// There is no compatible <see cref="System.Text.Json.Serialization.JsonConverter"/>
        /// for <typeparamref name="TValue"/> or its serializable members.
        /// </exception>
        [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
        [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
        public static ValueTask<TValue?> DeserializeAsync<TValue>(
            PipeReader utf8Json,
            JsonSerializerOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));

            JsonTypeInfo<TValue> jsonTypeInfo = GetTypeInfo<TValue>(options);
            return jsonTypeInfo.DeserializeAsync(utf8Json, cancellationToken);
        }

        /// <summary>
        /// Reads the UTF-8 encoded text representing a single JSON value into a <typeparamref name="TValue"/>.
        /// The PipeReader will be read to completion.
        /// </summary>
        /// <typeparam name="TValue">The type to deserialize the JSON value into.</typeparam>
        /// <returns>A <typeparamref name="TValue"/> representation of the JSON value.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="jsonTypeInfo">Metadata about the type to convert.</param>
        /// <param name="cancellationToken">
        /// The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> or <paramref name="jsonTypeInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="JsonException">
        /// The JSON is invalid,
        /// <typeparamref name="TValue"/> is not compatible with the JSON,
        /// or when there is remaining data in the PipeReader.
        /// </exception>
        public static ValueTask<TValue?> DeserializeAsync<TValue>(
                PipeReader utf8Json,
                JsonTypeInfo<TValue> jsonTypeInfo,
                CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));
            ArgumentNullException.ThrowIfNull(jsonTypeInfo, nameof(jsonTypeInfo));

            jsonTypeInfo.EnsureConfigured();
            return jsonTypeInfo.DeserializeAsync(utf8Json, cancellationToken);
        }

        /// <summary>
        /// Reads the UTF-8 encoded text representing a single JSON value into an instance specified by the <paramref name="jsonTypeInfo"/>.
        /// The PipeReader will be read to completion.
        /// </summary>
        /// <returns>A <paramref name="jsonTypeInfo"/> representation of the JSON value.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="jsonTypeInfo">Metadata about the type to convert.</param>
        /// <param name="cancellationToken">
        /// The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> or <paramref name="jsonTypeInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="JsonException">
        /// The JSON is invalid,
        /// or when there is remaining data in the PipeReader.
        /// </exception>
        public static ValueTask<object?> DeserializeAsync(
                PipeReader utf8Json,
                JsonTypeInfo jsonTypeInfo,
                CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));
            ArgumentNullException.ThrowIfNull(jsonTypeInfo, nameof(jsonTypeInfo));

            jsonTypeInfo.EnsureConfigured();
            return jsonTypeInfo.DeserializeAsObjectAsync(utf8Json, cancellationToken);
        }

        /// <summary>
        /// Reads the UTF-8 encoded text representing a single JSON value into a <paramref name="returnType"/>.
        /// The PipeReader will be read to completion.
        /// </summary>
        /// <returns>A <paramref name="returnType"/> representation of the JSON value.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="returnType">The type of the object to convert to and return.</param>
        /// <param name="context">A metadata provider for serializable types.</param>
        /// <param name="cancellationToken">
        /// The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/>, <paramref name="returnType"/>, or <paramref name="context"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="JsonException">
        /// The JSON is invalid,
        /// the <paramref name="returnType"/> is not compatible with the JSON,
        /// or when there is remaining data in the PipeReader.
        /// </exception>
        /// <exception cref="NotSupportedException">
        /// There is no compatible <see cref="System.Text.Json.Serialization.JsonConverter"/>
        /// for <paramref name="returnType"/> or its serializable members.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <see cref="JsonSerializerContext.GetTypeInfo(Type)"/> method on the provided <paramref name="context"/>
        /// did not return a compatible <see cref="JsonTypeInfo"/> for <paramref name="returnType"/>.
        /// </exception>
        public static ValueTask<object?> DeserializeAsync(
                PipeReader utf8Json,
                Type returnType,
                JsonSerializerContext context,
                CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));
            ArgumentNullException.ThrowIfNull(returnType, nameof(returnType));
            ArgumentNullException.ThrowIfNull(context, nameof(context));

            JsonTypeInfo jsonTypeInfo = GetTypeInfo(context, returnType);
            return jsonTypeInfo.DeserializeAsObjectAsync(utf8Json, cancellationToken);
        }

        /// <summary>
        /// Reads the UTF-8 encoded text representing a single JSON value into a <paramref name="returnType"/>.
        /// The PipeReader will be read to completion.
        /// </summary>
        /// <returns>A <paramref name="returnType"/> representation of the JSON value.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="returnType">The type of the object to convert to and return.</param>
        /// <param name="options">Options to control the behavior during reading.</param>
        /// <param name="cancellationToken">
        /// The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> or <paramref name="returnType"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="JsonException">
        /// The JSON is invalid,
        /// the <paramref name="returnType"/> is not compatible with the JSON,
        /// or when there is remaining data in the PipeReader.
        /// </exception>
        /// <exception cref="NotSupportedException">
        /// There is no compatible <see cref="System.Text.Json.Serialization.JsonConverter"/>
        /// for <paramref name="returnType"/> or its serializable members.
        /// </exception>
        [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
        [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
        public static ValueTask<object?> DeserializeAsync(
               PipeReader utf8Json,
               Type returnType,
               JsonSerializerOptions? options = null,
               CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));
            ArgumentNullException.ThrowIfNull(returnType, nameof(returnType));

            JsonTypeInfo jsonTypeInfo = GetTypeInfo(options, returnType);
            return jsonTypeInfo.DeserializeAsObjectAsync(utf8Json, cancellationToken);
        }

        /// <summary>
        /// Wraps the UTF-8 encoded text into an <see cref="IAsyncEnumerable{TValue}" />
        /// that can be used to deserialize root-level JSON arrays in a streaming manner.
        /// </summary>
        /// <typeparam name="TValue">The element type to deserialize asynchronously.</typeparam>
        /// <returns>An <see cref="IAsyncEnumerable{TValue}" /> representation of the provided JSON array.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="options">Options to control the behavior during reading.</param>
        /// <param name="cancellationToken">The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.</param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> is <see langword="null"/>.
        /// </exception>
        [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
        [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
        public static IAsyncEnumerable<TValue?> DeserializeAsyncEnumerable<TValue>(
                PipeReader utf8Json,
                JsonSerializerOptions? options = null,
                CancellationToken cancellationToken = default)
        {
            return DeserializeAsyncEnumerable<TValue>(utf8Json, topLevelValues: false, options, cancellationToken);
        }

        /// <summary>
        /// Wraps the UTF-8 encoded text into an <see cref="IAsyncEnumerable{TValue}" />
        /// that can be used to deserialize root-level JSON arrays in a streaming manner.
        /// </summary>
        /// <typeparam name="TValue">The element type to deserialize asynchronously.</typeparam>
        /// <returns>An <see cref="IAsyncEnumerable{TValue}" /> representation of the provided JSON array.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="jsonTypeInfo">Metadata about the element type to convert.</param>
        /// <param name="cancellationToken">The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.</param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> or <paramref name="jsonTypeInfo"/> is <see langword="null"/>.
        /// </exception>
        public static IAsyncEnumerable<TValue?> DeserializeAsyncEnumerable<TValue>(
                PipeReader utf8Json,
                JsonTypeInfo<TValue> jsonTypeInfo,
                CancellationToken cancellationToken = default)
        {
            return DeserializeAsyncEnumerable(utf8Json, jsonTypeInfo, topLevelValues: false, cancellationToken);
        }

        /// <summary>
        /// Wraps the UTF-8 encoded text into an <see cref="IAsyncEnumerable{TValue}" />
        /// that can be used to deserialize sequences of JSON values in a streaming manner.
        /// </summary>
        /// <typeparam name="TValue">The element type to deserialize asynchronously.</typeparam>
        /// <returns>An <see cref="IAsyncEnumerable{TValue}" /> representation of the provided JSON sequence.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="jsonTypeInfo">Metadata about the element type to convert.</param>
        /// <param name="topLevelValues">Whether to deserialize from a sequence of top-level JSON values.</param>
        /// <param name="cancellationToken">The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.</param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> or <paramref name="jsonTypeInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <remarks>
        /// When <paramref name="topLevelValues"/> is set to <see langword="true" />, treats the PipeReader as a sequence of
        /// whitespace separated top-level JSON values and attempts to deserialize each value into <typeparamref name="TValue"/>.
        /// When <paramref name="topLevelValues"/> is set to <see langword="false" />, treats the PipeReader as a JSON array and
        /// attempts to serialize each element into <typeparamref name="TValue"/>.
        /// </remarks>
        public static IAsyncEnumerable<TValue?> DeserializeAsyncEnumerable<TValue>(
            PipeReader utf8Json,
            JsonTypeInfo<TValue> jsonTypeInfo,
            bool topLevelValues,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));
            ArgumentNullException.ThrowIfNull(jsonTypeInfo, nameof(jsonTypeInfo));

            jsonTypeInfo.EnsureConfigured();
            return DeserializeAsyncEnumerableCore(utf8Json, jsonTypeInfo, topLevelValues, cancellationToken);
        }

        /// <summary>
        /// Wraps the UTF-8 encoded text into an <see cref="IAsyncEnumerable{TValue}" />
        /// that can be used to deserialize sequences of JSON values in a streaming manner.
        /// </summary>
        /// <typeparam name="TValue">The element type to deserialize asynchronously.</typeparam>
        /// <returns>An <see cref="IAsyncEnumerable{TValue}" /> representation of the provided JSON sequence.</returns>
        /// <param name="utf8Json">JSON data to parse.</param>
        /// <param name="topLevelValues"><see langword="true"/> to deserialize from a sequence of top-level JSON values, or <see langword="false"/> to deserialize from a single top-level array.</param>
        /// <param name="options">Options to control the behavior during reading.</param>
        /// <param name="cancellationToken">The <see cref="System.Threading.CancellationToken"/> that can be used to cancel the read operation.</param>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="utf8Json"/> is <see langword="null"/>.
        /// </exception>
        /// <remarks>
        /// When <paramref name="topLevelValues"/> is set to <see langword="true" />, treats the PipeReader as a sequence of
        /// whitespace separated top-level JSON values and attempts to deserialize each value into <typeparamref name="TValue"/>.
        /// When <paramref name="topLevelValues"/> is set to <see langword="false" />, treats the PipeReader as a JSON array and
        /// attempts to serialize each element into <typeparamref name="TValue"/>.
        /// </remarks>
        [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
        [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
        public static IAsyncEnumerable<TValue?> DeserializeAsyncEnumerable<TValue>(
            PipeReader utf8Json,
            bool topLevelValues,
            JsonSerializerOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(utf8Json, nameof(utf8Json));

            JsonTypeInfo<TValue> jsonTypeInfo = GetTypeInfo<TValue>(options);
            return DeserializeAsyncEnumerableCore(utf8Json, jsonTypeInfo, topLevelValues, cancellationToken);
        }

        private static IAsyncEnumerable<T?> DeserializeAsyncEnumerableCore<T>(
            PipeReader utf8Json,
            JsonTypeInfo<T> jsonTypeInfo,
            bool topLevelValues,
            CancellationToken cancellationToken)
        {
            Debug.Assert(jsonTypeInfo.IsConfigured);

            JsonTypeInfo<List<T?>> listTypeInfo;
            JsonReaderOptions readerOptions = jsonTypeInfo.Options.GetReaderOptions();
            if (topLevelValues)
            {
                listTypeInfo = GetOrAddListTypeInfoForRootLevelValueMode(jsonTypeInfo);
                readerOptions.AllowMultipleValues = true;
            }
            else
            {
                listTypeInfo = GetOrAddListTypeInfoForArrayMode(jsonTypeInfo);
            }

            return CreateAsyncEnumerableFromArray(utf8Json, listTypeInfo, readerOptions, cancellationToken);

            static async IAsyncEnumerable<T?> CreateAsyncEnumerableFromArray(
                PipeReader utf8Json,
                JsonTypeInfo<List<T?>> listTypeInfo,
                JsonReaderOptions readerOptions,
                [EnumeratorCancellation] CancellationToken cancellationToken)
            {
                Debug.Assert(listTypeInfo.IsConfigured);

                ReadStack readStack = default;
                readStack.Initialize(listTypeInfo, supportContinuation: true);
                JsonReaderState jsonReaderState = new(readerOptions);
                PipeReadBufferState bufferState = new(utf8Json);

                try
                {
                    bool success;
                    do
                    {
                        bufferState = await bufferState.ReadAsync(utf8Json, cancellationToken, fillBuffer: false).ConfigureAwait(false);
                        success = listTypeInfo.ContinueDeserialize<PipeReadBufferState, PipeReader>(
                            ref bufferState,
                            ref jsonReaderState,
                            ref readStack,
                            out List<T?>? _);

                        if (readStack.Current.ReturnValue is { } returnValue)
                        {
                            var list = (List<T?>)returnValue;
                            foreach (T? item in list)
                            {
                                yield return item;
                            }

                            list.Clear();
                        }
                    } while (!success);
                }
                finally
                {
                    bufferState.Dispose();
                }
            }
        }
    }
}
