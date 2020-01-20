/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.ratchet.securechat.keysrotation

import com.google.gson.annotations.SerializedName

/**
 * This class shows the result of rotateKeys operation.
 */
class RotationLog {

    /**
     * Number of unused one-time keys.
     */
    @SerializedName("one_time_keys_relevant")
    var oneTimeKeysRelevant = 0

    /**
     * NUmber of one-time keys that were generated and uploaded to the cloud during this operation.
     */
    @SerializedName("one_time_keys_added")
    var oneTimeKeysAdded = 0

    /**
     * Number of one-time keys that were deleted during this rotation.
     */
    @SerializedName("one_time_keys_deleted")
    var oneTimeKeysDeleted = 0

    /**
     * Number of one-time keys that were marked orphaned during this operation.
     */
    @SerializedName("one_time_keys_marks_orphaned")
    var oneTimeKeysMarkedOrphaned = 0

    /**
     * Number of one-time keys that were marked orphaned.
     */
    @SerializedName("one_time_keys_orphaned")
    var oneTimeKeysOrphaned = 0

    /**
     * Number of relevant long-term keys.
     */
    @SerializedName("long_term_keys_relevant")
    var longTermKeysRelevant = 0

    /**
     * Number of long-term keys that were generated and uploaded to the cloud during this operation.
     */
    @SerializedName("long_term_keys_added")
    var longTermKeysAdded = 0

    /**
     * Number of long-term keys that were deleted during this rotation.
     */
    @SerializedName("long_term_keys_deleted")
    var longTermKeysDeleted = 0

    /**
     * Number of long-term keys that were marked orphaned outdated this operation.
     */
    @SerializedName("long_term_keys_marked_outdated")
    var longTermKeysMarkedOutdated = 0

    /**
     * Number of long-term keys that were marked orphaned.
     */
    @SerializedName("long_term_keys_outdated")
    var longTermKeysOutdated = 0
}
