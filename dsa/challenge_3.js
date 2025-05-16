/**
 * @param {number[]} nums1
 * @param {number[]} nums2
 * @return {number}
 */
var findLength = function(nums1, nums2) {
    const n = nums1.length;  
    const m = nums2.length;  
    let maxLen = 0;

    for (let i = 0; i < n; i++) {
        for (let j = 0; j < m; j++) {
            let len = 0;
            while (i + len < n && j + len < m && nums1[i + len] === nums2[j + len]) {
                len++;
            }
            maxLen = Math.max(maxLen, len);
        }
    }
    return maxLen;
};