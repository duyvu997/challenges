/**
 * @param {number} n
 * @return {number[]}
 */
var grayCode = function(n) {
    const result = [0]; 

    for (let i = 0; i < n; i++) {
        const prefix = Math.pow(2, i);
        const len = result.length;

        for (let j = len - 1; j >= 0; j--) {
            result.push(result[j] + prefix);
        }
    }
    console.log(result)

    return result;
};

grayCode(4)