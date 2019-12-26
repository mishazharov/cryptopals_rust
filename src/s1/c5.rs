pub fn rand() -> u32 {
        2 + 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(rand(), 4);
    }
}
