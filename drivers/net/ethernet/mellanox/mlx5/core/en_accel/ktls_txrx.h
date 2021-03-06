/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#ifndef __MLX5E_KTLS_TXRX_H__
#define __MLX5E_KTLS_TXRX_H__

#ifdef CONFIG_MLX5_EN_TLS

#include <net/tls.h>
#include "en.h"
#include "en/txrx.h"

struct mlx5e_accel_tx_tls_state {
	u32 tls_tisn;
};

u16 mlx5e_ktls_get_stop_room(struct mlx5e_txqsq *sq);
u8 mlx5e_ktls_dumps_num_wqebbs(struct mlx5e_txqsq *sq, unsigned int nfrags,
			       unsigned int sync_len);

bool mlx5e_ktls_handle_tx_skb(struct tls_context *tls_ctx, struct mlx5e_txqsq *sq,
			      struct sk_buff *skb, int datalen,
			      struct mlx5e_accel_tx_tls_state *state);
void mlx5e_ktls_handle_rx_skb(struct mlx5e_rq *rq, struct sk_buff *skb,
			      struct mlx5_cqe64 *cqe, u32 *cqe_bcnt);

void mlx5e_ktls_handle_ctx_completion(struct mlx5e_icosq_wqe_info *wi);
void mlx5e_ktls_handle_get_psv_completion(struct mlx5e_icosq_wqe_info *wi,
					  struct mlx5e_icosq *sq);

void mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
					   struct mlx5e_tx_wqe_info *wi,
					   u32 *dma_fifo_cc);
#else
static inline void
mlx5e_ktls_tx_handle_resync_dump_comp(struct mlx5e_txqsq *sq,
				      struct mlx5e_tx_wqe_info *wi,
				      u32 *dma_fifo_cc)
{
}

#endif /* CONFIG_MLX5_EN_TLS */

#endif /* __MLX5E_TLS_TXRX_H__ */
