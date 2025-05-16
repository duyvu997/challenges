/**
 * @param {number} n
 * @param {number[][]} edges
 * @return {number[]}
 **/
function sumOfDistancesInTree(n, edges) {
    const tree = Array.from({ length: n }, () => []);
    for (const [u, v] of edges) {
        tree[u].push(v);
        tree[v].push(u);
    }

    const bfs = (start) => {
        const visited = Array(n).fill(false);
        const queue = [[start, 0]];
        let sum = 0;
        visited[start] = true;

        while (queue.length) {
            const [node, dist] = queue.shift();
            sum += dist;

            for (const neighbor of tree[node]) {
                if (!visited[neighbor]) {
                    visited[neighbor] = true;
                    queue.push([neighbor, dist + 1]);
                }
            }
        }

        return sum;
    };

    const result = [];
    for (let i = 0; i < n; i++) {
        result.push(bfs(i)*2);
    }
    console.log(result);
    
    return result
}